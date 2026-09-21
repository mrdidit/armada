# KPFE charging-kernel test

Experimental, not hardware-validated. This branch builds a signed test update
for KONKR Pocket FIT Elite; it is not a release or an upstream submission.

- Kernel source: Linux 7.2.3 on Armada `6027251e6c087d18433f0d1b0731b514ff217a25`.
- Existing AW99706 backlight fixes retained.
- Added patch: `0950-power-supply-qcom-battmgr-kpfe-charge-policy.patch`.
- Userspace base pinned to the existing `20260920.6027251` test image.
- Only the kernel package, initramfs and version metadata are replaced.
- No charging-policy service is installed or enabled.

The patch adds exact-KPFE `charge_behaviour` control and attachment/re-arm
handling, and improves errors from existing threshold controls. Kernel probe
can synchronize the default Auto policy through firmware; this is not a
passive telemetry-only change. Property readback is not electrical proof.

Host tests and a complete local kernel build passed. Initial device checks
will cover ordinary charging, cable-first bypass, restoration and bypass-first
attachment. Percentage-limit policy and desktop ownership remain separate.

GitHub Actions publishes only the branch test tag and an immutable build tag.
It does not publish a disk image or promote a release channel. Public build
information includes the source revision, base and result digests, kernel
package reference, patch checksum and signing evidence.

Installation and reboot require separate approval and a checked rollback
path. Use the verified image digest, not a moving tag.
