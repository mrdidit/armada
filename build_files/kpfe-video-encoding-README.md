# KPFE video encoding test

Standalone test image for the KONKR Pocket Fit Elite. It enables the existing
SM8750 Iris video codec and adds the encoder device path used by Steam.

The image uses official Armada testing `20261013.a30c39c` as its pinned base.
It is independent of the separate suspend test. Only the KPFE device tree is
compiled. The official kernel, modules, initramfs, Qualcomm firmware, Steam,
Proton and FEX packages are retained.

**Build KPFE video encoding test** runs for pushes to
`feat/kpfe-video-encoding-20261015` in `mrdidit/armada`, or by manual dispatch
from that branch. It compiles on native ARM64, checks that enabling Iris is the
only device-tree change, verifies the existing encoder module and compressed
firmware, and publishes a signed bootc image at:

`ghcr.io/mrdidit/armada:test-kpfe-video-encoding-20261015`

Each run saves its source revision, DTB hashes, base digest, image digest,
signatures and validation output in a `kpfe-encoding-build-evidence` artifact.
The workflow uses the existing fork `SIGNING_SECRET`; only its public key is
stored here. A failed validation does not update the test tag.

The DTB is a separate boot input: ostree includes it in the boot checksum,
and Armada's boot image updater appends it to the kernel. The existing
initramfs does not need regeneration for this change.

This is a hardware test candidate. Firmware authentication, Steam hardware
encoder selection and recording playback still need a test boot. No flashable
disk is produced by this workflow.
