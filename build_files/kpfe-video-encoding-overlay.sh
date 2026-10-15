#!/usr/bin/env bash
# Runs inside Containerfile.kpfe-video-encoding with networking disabled.
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
: "${DTB_REF:?DTB_REF is required}"

shopt -s nullglob
kernels=(/usr/lib/modules/*)
[[ ${#kernels[@]} -eq 1 && -d ${kernels[0]} ]] \
    || fail "expected exactly one installed kernel"
kernel_dir=${kernels[0]}
kernel_version=${kernel_dir##*/}
[[ ${kernel_version} == "${KPFE_ENCODING_KERNEL_VERSION}" ]] || fail "kernel version mismatch"
dtb=${kernel_dir}/dtb/qcom/sm8750-konkr-pf-elite.dtb
iris_module=${kernel_dir}/kernel/drivers/media/platform/qcom/iris/qcom-iris.ko

for artifact in vmlinuz initramfs.img .armada-source modules.dep \
    dtb/qcom/sm8750-konkr-pf-elite.dtb \
    kernel/drivers/media/platform/qcom/iris/qcom-iris.ko; do
    [[ -s ${kernel_dir}/${artifact} ]] || fail "missing base kernel artifact: ${artifact}"
done
for marker in 'qcom,sm8750-iris' 'qcom-iris-encoder' 'qcom/vpu/vpu35_p4.mbn'; do
    grep -aFq -- "${marker}" "${iris_module}" \
        || fail "base Iris module is missing ${marker}"
done
grep -Fxq "Source: linux-${kernel_version} (kernel.org stable)" \
    "${kernel_dir}/.armada-source" || fail "kernel source version mismatch"
grep -Fxq "Patches applied: ${KPFE_ENCODING_PATCH_COUNT} (from patches/series)" \
    "${kernel_dir}/.armada-source" || fail "base kernel patch count mismatch"

# Inspect the embedded config of the unchanged official Image, not a new config.
python3 - "${kernel_dir}/vmlinuz" <<'PY'
from pathlib import Path
import sys
import zlib
image = Path(sys.argv[1]).read_bytes()
marker = b'IKCFG_ST\x1f\x8b\x08'
pos = image.find(marker)
if pos < 0:
    raise SystemExit('ERROR: embedded base kernel config not found')
config = set(zlib.decompress(image[pos + 8:], 31).decode().splitlines())
for setting in ('CONFIG_VIDEO_QCOM_IRIS=m', 'CONFIG_FW_LOADER_COMPRESS=y',
                'CONFIG_FW_LOADER_COMPRESS_XZ=y', 'CONFIG_ARCH_QCOM=y'):
    if setting not in config:
        raise SystemExit(f'ERROR: base kernel lacks {setting}')
PY

# No board override or uncompressed shadow file: the driver uses this default.
firmware=/usr/lib/firmware/${KPFE_ENCODING_FIRMWARE}
[[ -s ${firmware} && ! -e ${firmware%.xz} ]] \
    || fail "default compressed Iris firmware is missing or shadowed"
printf '%s  %s\n' "${KPFE_ENCODING_FIRMWARE_SHA256}" "${firmware}" | sha256sum -c -
xz --test "${firmware}"

# Preserve the complete official kernel/module/initramfs/other-DTB set.
find "${kernel_dir}" -type f ! -path "${dtb}" -print0 | sort -z \
    | xargs -0 sha256sum > /tmp/kpfe-encoding-kernel.before
rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
    | sort > /tmp/kpfe-encoding-rpms.before

(cd /dtb && sha256sum -c SHA256SUMS)
install -m0644 /dtb/sm8750-konkr-pf-elite.dtb "${dtb}"
install -Dm0644 /ctx/system_files/usr/lib/udev/rules.d/70-armada-video-codec.rules \
    /usr/lib/udev/rules.d/70-armada-video-codec.rules
udevadm verify /usr/lib/udev/rules.d/70-armada-video-codec.rules
printf '%s\n' "${ARMADA_VERSION}" > /usr/lib/armada/version
bash /ctx/build_files/52-configure-os-release.sh

# DTBs are separate boot inputs. ostree hashes their directory and Armada's
# bootimg updater appends them to Image; no initramfs regeneration is needed.
sha256sum --check --quiet /tmp/kpfe-encoding-kernel.before
rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
    | sort > /tmp/kpfe-encoding-rpms.after
cmp /tmp/kpfe-encoding-rpms.before /tmp/kpfe-encoding-rpms.after \
    || fail "installed RPMs changed from the official testing image"

install -d -m 0755 /usr/share/armada
cp /ctx/build_files/kpfe-video-encoding.env /usr/share/armada/kpfe-video-encoding.env
cp /dtb/dtb-source.txt /usr/share/armada/kpfe-video-encoding-source.txt
{
    printf 'ARMADA_VERSION=%q\n' "${ARMADA_VERSION}"
    printf 'DTB_REF=%q\n' "${DTB_REF}"
    printf 'KERNEL_VERSION=%q\n' "${kernel_version}"
    printf 'KERNEL_SHA256=%q\n' "$(sha256sum "${kernel_dir}/vmlinuz" | cut -d ' ' -f 1)"
    printf 'INITRAMFS_SHA256=%q\n' "$(sha256sum "${kernel_dir}/initramfs.img" | cut -d ' ' -f 1)"
    printf 'KPFE_DTB_SHA256=%q\n' "$(sha256sum "${dtb}" | cut -d ' ' -f 1)"
} >> /usr/share/armada/kpfe-video-encoding.env
chmod 0644 /usr/share/armada/kpfe-video-encoding.env

printf 'Verified KPFE codec DTB, firmware and udev rule; kernel, initramfs and RPMs unchanged (%s).\n' \
    "${KPFE_ENCODING_BASE_VERSION}"
