#!/usr/bin/env bash
# Build one DTB from the same complete source inputs as the official kernel.
set -euo pipefail
export LC_ALL=C ARCH=arm64

source /src/kpfe-video-encoding.env
source /src/kernel/BASE.env
[[ ${VERSION} == "${KPFE_ENCODING_KERNEL_VERSION}" ]]
[[ $(uname -m) == aarch64 ]]

mkdir -p /tmp/kpfe-dtb /out
cd /tmp/kpfe-dtb
archive=linux-${VERSION}.tar.xz
curl --fail --location --retry 3 \
    "https://cdn.kernel.org/pub/linux/kernel/v${VERSION%%.*}.x/${archive}" -o "${archive}"
printf '%s  %s\n' "${KPFE_ENCODING_SOURCE_SHA256}" "${archive}" | sha256sum -c -
tar -xf "${archive}"
cd "linux-${VERSION}"

# Apply the complete series in order. Count every applied hunk to reject a
# truncated/malformed patch; no dry-run is used for multipart DTS patches.
applied=0
while IFS= read -r line; do
    line=${line%%#*}
    [[ -n ${line//[[:space:]]/} ]] || continue
    read -r name extra <<< "${line}"
    [[ -z ${extra} && -f /src/kernel/patches/${name} ]]
    patch_file=/src/kernel/patches/${name}
    expected=$(grep -c '^@@ ' "${patch_file}")
    patch -p1 --batch --forward -F0 --verbose --no-backup-if-mismatch \
        < "${patch_file}" > /tmp/kpfe-dtb/patch.log 2>&1 || {
        cat /tmp/kpfe-dtb/patch.log
        exit 1
    }
    actual=$(grep -c '^Hunk #[0-9].*succeeded' /tmp/kpfe-dtb/patch.log)
    [[ ${actual} -eq ${expected} ]]
    applied=$((applied + 1))
done < /src/kernel/patches/series
[[ ${applied} -eq ${KPFE_ENCODING_PATCH_COUNT} ]]

cp /src/kernel/dts/*.dts /src/kernel/dts/*.dtsi arch/arm64/boot/dts/qcom/
for patch_file in /src/kernel/dts/*.patch; do
    patch -p1 --batch --forward -F0 --no-backup-if-mismatch < "${patch_file}"
done
printf '\ndtb-$(CONFIG_ARCH_QCOM) += sm8750-konkr-pf-elite.dtb\n' \
    >> arch/arm64/boot/dts/qcom/Makefile

make defconfig
sed -E '/^[[:space:]]*CONFIG_[A-Z0-9_]+=/ s/[[:space:]]*#.*$//' \
    /src/kernel/config/armada-kernel.config.overrides > /tmp/kpfe-dtb/config.fragment
bash scripts/kconfig/merge_config.sh .config /tmp/kpfe-dtb/config.fragment
make -j"$(nproc)" qcom/sm8750-konkr-pf-elite.dtb

cp arch/arm64/boot/dts/qcom/sm8750-konkr-pf-elite.dtb /out/
cp .config /out/dtb-build.config
{
    printf 'Source: linux-%s (kernel.org stable)\n' "${VERSION}"
    printf 'Source SHA256: %s\n' "${KPFE_ENCODING_SOURCE_SHA256}"
    printf 'Patches applied: %s (from patches/series)\n' "${applied}"
    printf 'Built: KPFE DTB only on aarch64\n'
} > /out/dtb-source.txt
cd /out
sha256sum sm8750-konkr-pf-elite.dtb > SHA256SUMS
