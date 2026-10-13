#!/usr/bin/env bash
# Runs inside Containerfile.pr712-test with networking disabled.
set -euo pipefail
export LC_ALL=C

source /ctx/build_files/pr712-test.env

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

[[ ${BASE_IMAGE:?BASE_IMAGE is required} == "${PR712_BASE_IMAGE}" ]] \
    || fail "base image does not match the locked upstream test image"
[[ $(</usr/lib/armada/version) == "${PR712_BASE_VERSION}" ]] \
    || fail "base image version does not match ${PR712_BASE_VERSION}"
[[ ${ARMADA_VERSION:?ARMADA_VERSION is required} =~ ^[a-z0-9][a-z0-9._-]*$ ]] \
    || fail "invalid test version"
[[ ${ARMADA_VERSION} != "${PR712_BASE_VERSION}" ]] \
    || fail "the test build must have its own version"
: "${KERNEL_REF:?KERNEL_REF is required}"

# No userspace package transaction is allowed in this kernel-only overlay.
rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
    | sort > /tmp/pr712-rpms.before

bash /ctx/build_files/20-install-kernel.sh
printf '%s\n' "${ARMADA_VERSION}" > /usr/lib/armada/version
bash /ctx/build_files/52-configure-os-release.sh
bash /ctx/build_files/55-generate-initramfs.sh

rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
    | sort > /tmp/pr712-rpms.after
cmp /tmp/pr712-rpms.before /tmp/pr712-rpms.after \
    || fail "installed RPMs changed from the upstream test image"

shopt -s nullglob
kernels=(/usr/lib/modules/*)
[[ ${#kernels[@]} -eq 1 && -d ${kernels[0]} ]] \
    || fail "expected exactly one installed kernel"
kernel_dir=${kernels[0]}
kernel_version=${kernel_dir##*/}

for artifact in \
    vmlinuz \
    initramfs.img \
    .armada-source \
    modules.builtin \
    modules.builtin.modinfo \
    dtb/qcom/sm8750-konkr-pf-elite.dtb; do
    [[ -s ${kernel_dir}/${artifact} ]] \
        || fail "missing kernel artifact: ${artifact}"
done

# JOYSTICK_MCU is built in. Verify the compiled Image, not merely patch text.
for marker in \
    'MCU power cut for suspend' \
    'resume: power cycling the MCU' \
    'mcu_joystick.power_off_in_suspend'; do
    grep -aFq -- "${marker}" "${kernel_dir}/vmlinuz" \
        || fail "compiled kernel is missing PR #712 marker: ${marker}"
done
grep -Fxq 'kernel/drivers/input/joystick/mcu_joystick.ko' \
    "${kernel_dir}/modules.builtin" \
    || fail "the MCU joystick driver is not built into the kernel"
grep -aFq 'mcu_joystick.parm=power_off_in_suspend:' \
    "${kernel_dir}/modules.builtin.modinfo" \
    || fail "the compiled MCU driver lacks its suspend A/B parameter"
grep -Fxq "Source: linux-${kernel_version} (kernel.org stable)" \
    "${kernel_dir}/.armada-source" \
    || fail "kernel source metadata does not match the installed version"

install -d -m 0755 /usr/share/armada
cp /ctx/build_files/pr712-test.env /usr/share/armada/pr712-test.env
{
    printf 'ARMADA_VERSION=%q\n' "${ARMADA_VERSION}"
    printf 'KERNEL_REF=%q\n' "${KERNEL_REF}"
    printf 'KERNEL_VERSION=%q\n' "${kernel_version}"
    printf 'KERNEL_SHA256=%q\n' "$(sha256sum "${kernel_dir}/vmlinuz" | cut -d ' ' -f 1)"
} >> /usr/share/armada/pr712-test.env
chmod 0644 /usr/share/armada/pr712-test.env

printf 'Verified PR #712 kernel %s over unchanged upstream RPMs (%s).\n' \
    "${kernel_version}" "${PR712_BASE_VERSION}"
