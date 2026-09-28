# KPFE scoped charging-policy test

Experimental KPFE image; changed behavior requires hardware retesting.

- Base: `ghcr.io/mrdidit/armada@sha256:3ad2d5de4575d8fffacc92a77aae6a382f9a0066818f5f99e8de3d35cb26313c`.
- Verified input revision: `fe40096cb558bce99978223974357486500e5931`, build `36397464944`.
- Reuse the completed Linux 7.2.3 kernel, modules and DTBs. Replace only
  charging patch 0950 relative to the retained charging/sleep kernel sources.
- Install the four verified runtime RPMs: charging policy, PowerDevil,
  UPower and UPower-libs. No kernel or RPM compilation in this workflow.
- Regenerate initramfs for the replacement modules. Retain firmware,
  sleep/backlight support, boot-image update machinery and unrelated packages.
- The KPFE request/reply and lifecycle changes use exact device match data;
  unmatched devices retain the preceding Qualcomm driver paths.
- After reviewed one-time setup, authorization persists. Reboot preserves
  Normal or the exact Limit pair; Bypass becomes Normal. Same-boot service
  restart preserves the selected policy and does not clear conflicts.
- Image defaults remain disabled and unvalidated. No enrollment, grants,
  service activation or live charging writes are performed by assembly.

Only `test-kpfe-scoped-policy-20260928` and unique build tags are published.
Existing test tags, release channels and upstream PRs are unchanged.
The image is signed with the same test key as the pinned base.

Assembly validates the exact input inventory and hashes, the offline RPM
transaction, protected filesystem metadata, kernel package and generated
initramfs. Build success is not boot or electrical validation. Existing
on-device policy configuration persists through an update; changed integration
hashes require a reviewed one-time migration, not authorization at every boot.

Corresponding RPM sources and kernel source archives are included under
`/usr/share/armada-charging/`. Original licenses and notices are retained.
The clean kernel inputs preserve Armada baseline `710024aa00c63cd86620c1d9103f8bb0c6117b10`
with the corrected patch; private investigation archives are not included.

The assembly/signing pattern and retained scripts derive from fork revision
`ad955153c825b2b75e11db67b1c1e7ef12bc225e`. The original verifier in the kernel
input archive remains unchanged; its expected charging-patch hash is adapted
in memory for package verification.

Installation is separate. Use the independently verified image digest and
retain a known-good deployment for rollback. This workflow neither accesses
the device nor stages an update or reboot.
