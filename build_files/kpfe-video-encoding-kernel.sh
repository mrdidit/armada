#!/usr/bin/env bash
# Wrap the normal kernel package build; never install packages into the OS image.
set -euo pipefail
export LC_ALL=C

source /src/kpfe-video-encoding.env
source /work/BASE.env
[[ $(uname -m) == aarch64 ]]
[[ ${VERSION} == "${KPFE_ENCODING_KERNEL_VERSION}" ]]
[[ -z ${FAST:-} ]] || { echo 'ERROR: a fresh kernel build is required' >&2; exit 1; }

patch_count=$(sed 's/#.*//' /work/patches/series | awk 'NF { count++ } END { print count+0 }')
[[ ${patch_count} -eq ${KPFE_ENCODING_PATCH_COUNT} ]]

# build.sh uses this exact work directory and reuses an existing archive.
# Verify the locked source before its normal extraction/patch/config pipeline.
dnf -y install curl xz
build_dir=/tmp/armada-kernel-build
mkdir -p "${build_dir}"
archive=${build_dir}/linux-${VERSION}.tar.xz
curl --fail --location --retry 3 \
    "https://cdn.kernel.org/pub/linux/kernel/v${VERSION%%.*}.x/linux-${VERSION}.tar.xz" \
    -o "${archive}"
printf '%s  %s\n' "${KPFE_ENCODING_SOURCE_SHA256}" "${archive}" | sha256sum -c -

cd /work
bash ./build.sh

source_dir=${build_dir}/linux-${VERSION}
# Do not run make again with different CC arguments: it can resync .config.
kernel_release=$(<"${source_dir}/include/config/kernel.release")
[[ ${kernel_release} == "${KPFE_ENCODING_KERNEL_VERSION}" ]]
tarball=armada-kernel-${kernel_release}.tar.zst
[[ -s /work/out/${tarball} && -s /work/out/${tarball}.sha256 ]]
(cd /work/out && sha256sum -c "${tarball}.sha256")

# Retain the exact config and symbol versions for subsequent module audits.
install -m0644 "${source_dir}/.config" /work/out/kernel-build.config
install -m0644 "${source_dir}/Module.symvers" /work/out/Module.symvers
[[ -s /work/out/Module.symvers ]]
{
    printf 'Source: linux-%s (kernel.org stable)\n' "${VERSION}"
    printf 'Source SHA256: %s\n' "${KPFE_ENCODING_SOURCE_SHA256}"
    printf 'Kernel release: %s\n' "${kernel_release}"
    printf 'Patches applied: %s (from patches/series)\n' "${patch_count}"
    printf 'Built: complete Image, modules and DTBs on aarch64\n'
    printf 'Compiler: %s\n' "$(sed -n 's/^CONFIG_CC_VERSION_TEXT="\(.*\)"$/\1/p' "${source_dir}/.config")"
    rpm -q gcc binutils dwarves
} > /work/out/kernel-source.txt

cd /work/out
sha256sum "${tarball}" "${tarball}.sha256" kernel-build.config Module.symvers \
    kernel-source.txt > SHA256SUMS

# Do not retain compiler objects or the source archive in the builder layer.
rm -rf -- "${build_dir}"
dnf clean all
