# KPFE video encoding test

Standalone test image for the KONKR Pocket Fit Elite. It enables the SM8750
Iris video codec and adds encoder compatibility fixes for Steam recording.

The image uses official Armada testing `20261013.a30c39c` as its pinned base.
It is independent of the separate suspend test. The normal Armada kernel,
modules and device trees are rebuilt with two Iris fixes, and a fresh initramfs
is generated. Qualcomm firmware, Steam, Proton, FEX and the other installed
packages stay at the pinned base versions.

**Build KPFE video encoding test** is launched manually from
`feat/kpfe-video-encoding-20261015` in `mrdidit/armada`.
It compiles on native ARM64, checks the kernel configuration and the KPFE
device-tree change, verifies module compatibility and compressed firmware,
and publishes a signed bootc image at:

`ghcr.io/mrdidit/armada:test-kpfe-video-encoding-20261015`

Dispatch the existing `build.yml` workflow with this feature branch selected:

```sh
gh workflow run build.yml --repo mrdidit/armada --ref feat/kpfe-video-encoding-20261015
```

On this branch it calls
the encoder test workflow and skips the normal package, image and disk builds.
This does not require changing the default branch.

Each run saves its source revision, kernel configuration, symbol versions,
artifact hashes, base digest, image digest, signatures and validation output
in a `kpfe-encoding-build-evidence` artifact.
The workflow uses the existing fork `SIGNING_SECRET`; only its public key is
stored here. A failed validation does not update the test tag.

The previous image exposed the hardware encoder successfully. A synthetic
test produced 90 decodable frames, but the driver omitted the keyframe flags
Steam needs to start a recording. This candidate adds picture-type reporting
and the standard force-keyframe control. Recording and playback still need
validation after the new kernel boots.

The complete kernel tree is replaced together, then the base image's dracut
generates its initramfs. Armada's existing boot updater assembles the device
boot image after deployment. No flashable disk is produced by this workflow.
