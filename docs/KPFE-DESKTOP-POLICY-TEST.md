# KPFE desktop charging-policy test

Experimental image assembly; hardware validation is pending.

- Base: `ghcr.io/mrdidit/armada@sha256:3ad2d5de4575d8fffacc92a77aae6a382f9a0066818f5f99e8de3d35cb26313c`.
- Replace only PowerDevil, UPower and UPower-libs; add the disabled
  `armada-charging` package from verified package run `35854292032`.
- Package source revision: `543a4f12bd834897a9ec577c7a485080b19ca1df`.
- Preserve kernel 7.2.3, initramfs, DTBs, firmware, sleep/backlight fixes and
  existing boot-image update machinery. No kernel or package rebuild.
- Device validation, ownership and development gates remain disabled;
  installation does not enroll a battery or enable the policy service.
- Only `test-kpfe-desktop-policy-20260923` and unique build tags are published.
  Release channels, the older kernel-test tag and upstream PRs are untouched.

The native ARM64 assembly performs an offline RPM transaction with dependency
checking, verifies its exact package delta, checks protected filesystem content
and metadata, and runs bootc lint. Chunkah retains the existing image's runtime
configuration and xattr grouping. The exact image digest is signed with the
same mrdidit test-image key as the base.

Four runtime RPMs, their three matching rebuilt source RPMs and checksums are
transferred through an unpublished draft release. This excludes private notes.
Corresponding source RPMs are also included in the public image at
`/usr/share/armada-charging/source-rpms/`; they contain the specs, sources,
patches and retained upstream notices. The runtime package retains its license
files. PowerDevil and UPower remain upstream projects; integration is not a
claim of their authorship. Existing files and imported notices are preserved.

The serialization/signing pattern is adapted from `.github/workflows/build.yml`
and `Containerfile.charging-test` at Armada fork commit
`710024aa00c63cd86620c1d9103f8bb0c6117b10`. The unchanged os-release and Steam
verification helpers are reused from that same tree. The public signing key
matches the previously verified 22 September test build.

Use the verified digest for separately approved staging. Keep the currently
booted image as rollback; reboot and charging activation are separate steps.
The existing boot-image updater will embed the staged deployment's OSTree
command line during finalization; unchanged kernel payload is not a claim that
the ESP boot-image bytes remain identical across reboot.
