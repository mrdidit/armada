#!/usr/bin/env bash
# Runs only inside the disposable image build, with networking disabled.
set -euo pipefail
export LC_ALL=C

source /ctx/build_files/kpfe-video-encoding.env

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

[[ ${BASE_IMAGE:?BASE_IMAGE is required} == "${KPFE_ENCODING_BASE_IMAGE}" ]] \
    || fail "base image does not match the locked official testing image"
[[ $(</usr/lib/armada/version) == "${KPFE_ENCODING_BASE_VERSION}" ]] \
    || fail "base image version does not match ${KPFE_ENCODING_BASE_VERSION}"
[[ ${ARMADA_VERSION:?ARMADA_VERSION is required} =~ ^20261015\.kpfe-encoding\.[a-f0-9]{7}$ ]] \
    || fail "invalid codec test version"
: "${KERNEL_REF:?KERNEL_REF is required}"

shopt -s nullglob
kernels=(/usr/lib/modules/*)
[[ ${#kernels[@]} -eq 1 && -d ${kernels[0]} ]] \
    || fail "expected exactly one installed kernel"
kernel_dir=${kernels[0]}
kernel_version=${kernel_dir##*/}
[[ ${kernel_version} == "${KPFE_ENCODING_KERNEL_VERSION}" ]] || fail "base kernel version mismatch"
dtb=${kernel_dir}/dtb/qcom/sm8750-konkr-pf-elite.dtb
iris_module=${kernel_dir}/kernel/drivers/media/platform/qcom/iris/qcom-iris.ko

for artifact in vmlinuz initramfs.img .armada-source modules.dep \
    dtb/qcom/sm8750-konkr-pf-elite.dtb \
    kernel/drivers/media/platform/qcom/iris/qcom-iris.ko; do
    [[ -s ${kernel_dir}/${artifact} ]] || fail "missing base kernel artifact: ${artifact}"
done
grep -Fxq "Source: linux-${kernel_version} (kernel.org stable)" \
    "${kernel_dir}/.armada-source" || fail "base kernel source version mismatch"
grep -Fxq "Patches applied: ${KPFE_ENCODING_BASE_PATCH_COUNT} (from patches/series)" \
    "${kernel_dir}/.armada-source" || fail "base kernel patch count mismatch"
base_iris_sha256=$(sha256sum "${iris_module}" | cut -d ' ' -f 1)

# This base already uses an unpackaged Armada kernel. No RPM transaction or
# firmware recopy is needed; fail if the premise changes.
rpm -qa --qf '%{NAME}\n' > /tmp/kpfe-encoding-rpm-names
if grep -Exq 'kernel|kernel-core|kernel-modules|kernel-modules-core' /tmp/kpfe-encoding-rpm-names; then
    fail "base contains an RPM kernel; refusing an unmanaged replacement"
fi
rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
    | sort > /tmp/kpfe-encoding-rpms.before
find /usr/lib/firmware -type f -print0 | sort -z \
    | xargs -0 sha256sum > /tmp/kpfe-encoding-firmware.before
find /usr/lib/firmware -type l -printf '%p -> %l\n' | sort \
    > /tmp/kpfe-encoding-firmware-links.before

# Keep the existing default firmware and compressed-loader configuration.
firmware=/usr/lib/firmware/${KPFE_ENCODING_FIRMWARE}
[[ -s ${firmware} && ! -e ${firmware%.xz} ]] \
    || fail "default compressed Iris firmware is missing or shadowed"
printf '%s  %s\n' "${KPFE_ENCODING_FIRMWARE_SHA256}" "${firmware}" | sha256sum -c -
xz --test "${firmware}"

tarballs=(/kernel/armada-kernel-*.tar.zst)
[[ ${#tarballs[@]} -eq 1 ]] || fail "expected one replacement kernel tarball"
tarball=${tarballs[0]}
[[ ${tarball##*/} == "armada-kernel-${kernel_version}.tar.zst" ]] \
    || fail "replacement kernel filename/version mismatch"
for artifact in SHA256SUMS kernel-build.config Module.symvers kernel-source.txt; do
    [[ -s /kernel/${artifact} ]] || fail "missing kernel build evidence: ${artifact}"
done
(cd /kernel && sha256sum -c SHA256SUMS && sha256sum -c "${tarball##*/}.sha256")
grep -Fxq "Source SHA256: ${KPFE_ENCODING_SOURCE_SHA256}" /kernel/kernel-source.txt \
    || fail "replacement source hash mismatch"
grep -Fxq "Kernel release: ${kernel_version}" /kernel/kernel-source.txt \
    || fail "replacement kernel release mismatch"
grep -Fxq "Patches applied: ${KPFE_ENCODING_PATCH_COUNT} (from patches/series)" \
    /kernel/kernel-source.txt || fail "replacement patch count mismatch"

# Restrict extraction to the expected kernel tree, then inspect it before
# replacing the old tree. Keeping the old modules alongside new ones is unsafe.
tar --list --zstd -f "${tarball}" > /tmp/kpfe-encoding-tar-paths
python3 - "${kernel_version}" /tmp/kpfe-encoding-tar-paths <<'PY'
from pathlib import Path, PurePosixPath
import sys
root = f'lib/modules/{sys.argv[1]}'
for name in Path(sys.argv[2]).read_text().splitlines():
    clean = name.rstrip('/')
    if (PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
            or not (clean in ('lib', 'lib/modules', root) or clean.startswith(root + '/'))):
        raise SystemExit(f'ERROR: unexpected kernel archive path: {name}')
PY
mkdir -p /tmp/kpfe-encoding-kernel
tar --extract --zstd -f "${tarball}" -C /tmp/kpfe-encoding-kernel/
new_kernel=/tmp/kpfe-encoding-kernel/lib/modules/${kernel_version}
[[ -d ${new_kernel} && ! -L ${new_kernel} ]] || fail "missing replacement kernel tree"
for artifact in vmlinuz .armada-source modules.builtin modules.builtin.modinfo \
    dtb/qcom/sm8750-konkr-pf-elite.dtb \
    kernel/drivers/media/platform/qcom/iris/qcom-iris.ko; do
    [[ -s ${new_kernel}/${artifact} ]] || fail "missing replacement kernel artifact: ${artifact}"
done
[[ ! -e ${new_kernel}/build && ! -e ${new_kernel}/source && ! -e ${new_kernel}/initramfs.img ]] \
    || fail "unexpected build links or prebuilt initramfs in replacement kernel"
grep -Fxq "Patches applied: ${KPFE_ENCODING_PATCH_COUNT} (from patches/series)" \
    "${new_kernel}/.armada-source" || fail "packaged kernel patch count mismatch"

# Verify the embedded Image config, not just the supplied config text.
python3 - "${new_kernel}/vmlinuz" /kernel/kernel-build.config "${kernel_dir}/vmlinuz" <<'PY'
from pathlib import Path
import json
import re
import sys
import zlib
def extract_config(path):
    image = Path(path).read_bytes()
    pos = image.find(b'IKCFG_ST\x1f\x8b\x08')
    if pos < 0:
        raise SystemExit(f'ERROR: embedded kernel config not found: {path}')
    return zlib.decompress(image[pos + 8:], 31).decode()

embedded = extract_config(sys.argv[1])
if embedded != Path(sys.argv[2]).read_text():
    raise SystemExit('ERROR: embedded and supplied kernel configs differ')
config = set(embedded.splitlines())
for setting in ('CONFIG_VIDEO_QCOM_IRIS=m', 'CONFIG_FW_LOADER_COMPRESS=y',
                'CONFIG_FW_LOADER_COMPRESS_XZ=y', 'CONFIG_ARCH_QCOM=y'):
    if setting not in config:
        raise SystemExit(f'ERROR: replacement kernel lacks {setting}')

def settings(text):
    result = {}
    for line in text.splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            name, value = line.split('=', 1)
            result[name] = value
        else:
            match = re.fullmatch(r'# (CONFIG_\w+) is not set', line)
            if match:
                result[match[1]] = 'n'
    return result

base = settings(extract_config(sys.argv[3]))
candidate = settings(embedded)
changes = {key: {'base': base.get(key), 'candidate': candidate.get(key)}
           for key in sorted(base.keys() | candidate.keys())
           if base.get(key) != candidate.get(key)}
identity = {'CONFIG_CC_VERSION_TEXT', 'CONFIG_GCC_VERSION', 'CONFIG_AS_VERSION',
            'CONFIG_LD_VERSION', 'CONFIG_PAHOLE_VERSION'}
Path('/tmp/kpfe-encoding-config-diff.json').write_text(json.dumps(changes, indent=2) + '\n')
unexpected = changes.keys() - identity
if unexpected:
    raise SystemExit(f'ERROR: kernel configuration changed: {sorted(unexpected)}')
print('Kernel configuration differences (tool versions only):', json.dumps(changes))
PY

new_iris=${new_kernel}/kernel/drivers/media/platform/qcom/iris/qcom-iris.ko
[[ $(modinfo -F vermagic "${new_iris}") == "${kernel_version} "* ]] \
    || fail "replacement Iris module vermagic mismatch"
[[ $(sha256sum "${new_iris}" | cut -d ' ' -f 1) != "${base_iris_sha256}" ]] \
    || fail "Iris module is unchanged from the base"
for marker in 'qcom,sm8750-iris' 'qcom-iris-encoder' 'qcom/vpu/vpu35_p4.mbn'; do
    grep -aFq -- "${marker}" "${new_iris}" || fail "replacement Iris module is missing ${marker}"
done
while IFS= read -r board; do
    [[ -n ${board} ]] || continue
    [[ -s ${new_kernel}/dtb/qcom/${board}.dtb ]] || fail "missing supported DTB: ${board}"
done < /usr/lib/armada/supported-dtbs

rm -rf -- "${kernel_dir}"
mv -- "${new_kernel}" "${kernel_dir}"
depmod -a "${kernel_version}" -b /
kernels=(/usr/lib/modules/*)
[[ ${#kernels[@]} -eq 1 && ${kernels[0]} == "${kernel_dir}" ]] \
    || fail "replacement left multiple kernel trees"
[[ -s ${kernel_dir}/modules.dep ]] || fail "module dependency map was not generated"
install -Dm0644 /ctx/system_files/usr/lib/udev/rules.d/70-armada-video-codec.rules \
    /usr/lib/udev/rules.d/70-armada-video-codec.rules
udevadm verify /usr/lib/udev/rules.d/70-armada-video-codec.rules
printf '%s\n' "${ARMADA_VERSION}" > /usr/lib/armada/version
bash /ctx/build_files/52-configure-os-release.sh

# Use the base image's dracut, firmware, splash and OSTree integration. This
# script validates required initrd content and uses the explicit kernel release.
bash /ctx/build_files/55-generate-initramfs.sh
[[ -s ${kernel_dir}/initramfs.img ]] || fail "initramfs generation produced no image"

find /usr/lib/firmware -type f -print0 | sort -z \
    | xargs -0 sha256sum > /tmp/kpfe-encoding-firmware.after
cmp /tmp/kpfe-encoding-firmware.before /tmp/kpfe-encoding-firmware.after \
    || fail "firmware files changed"
find /usr/lib/firmware -type l -printf '%p -> %l\n' | sort \
    > /tmp/kpfe-encoding-firmware-links.after
cmp /tmp/kpfe-encoding-firmware-links.before /tmp/kpfe-encoding-firmware-links.after \
    || fail "firmware symlinks changed"
rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
    | sort > /tmp/kpfe-encoding-rpms.after
cmp /tmp/kpfe-encoding-rpms.before /tmp/kpfe-encoding-rpms.after \
    || fail "installed RPMs changed from the official testing image"

install -d -m0755 /usr/share/armada
cp /ctx/build_files/kpfe-video-encoding.env /usr/share/armada/kpfe-video-encoding.env
cp /kernel/kernel-source.txt /usr/share/armada/kpfe-video-encoding-source.txt
cp /tmp/kpfe-encoding-config-diff.json /usr/share/armada/kpfe-video-encoding-config-diff.json
{
    printf 'ARMADA_VERSION=%q\n' "${ARMADA_VERSION}"
    printf 'KERNEL_REF=%q\n' "${KERNEL_REF}"
    printf 'KERNEL_VERSION=%q\n' "${kernel_version}"
    printf 'KERNEL_SHA256=%q\n' "$(sha256sum "${kernel_dir}/vmlinuz" | cut -d ' ' -f 1)"
    printf 'INITRAMFS_SHA256=%q\n' "$(sha256sum "${kernel_dir}/initramfs.img" | cut -d ' ' -f 1)"
    printf 'IRIS_MODULE_SHA256=%q\n' "$(sha256sum "${iris_module}" | cut -d ' ' -f 1)"
    printf 'KPFE_DTB_SHA256=%q\n' "$(sha256sum "${dtb}" | cut -d ' ' -f 1)"
} >> /usr/share/armada/kpfe-video-encoding.env
chmod 0644 /usr/share/armada/kpfe-video-encoding.env

printf 'Verified replacement kernel and initramfs; firmware and RPMs preserved from %s.\n' \
    "${KPFE_ENCODING_BASE_VERSION}"
