# KPFE preview candidate

Base: `b031deef99a095104ef234c5a0705850152dffe1`, successful preview build
[42931170641](https://github.com/armada-os/armada/actions/runs/42931170641),
11 November 2026. Kernel: Linux 7.2.6. Gamescope: Terra recipe
`96445611095dc1ac9aadf5eb520eb0bcbf7fec5c`, OGC `3.17.0-ogc1`.

The audit compares effective source paths and board configuration. Open PR
status alone does not establish whether a fix is missing.

| Area | Preview implementation | Candidate |
| --- | --- | --- |
| Chipone | Original vendor driver; no panel follower or KPFE panel reference | Carry #745 lifecycle handling and panel reference |
| Iris | KPFE codec disabled; encoder metadata subscription, dynamic force-keyframe control and shared control lock absent | Carry #737 encoder fixes, enable codec and add Steam video-enc0 alias |
| Gamescope recording | Newer base still dequeues on the compositor side and can overwrite the pending buffer | Carry the upstream PipeWire ownership fix from #737 |
| SoCCP | Driver, shared SM8750 node and KPFE firmware already present | Retain preview code; firmware blob matches the historical baseline |
| PCIe power | Old 0044 retention and 0521 suspend-floor additions absent; OFF/ON GDSCs and endpoint D3cold handling present | Retain preview code |
| PCIe/display CESTA | Optional historical AOSD additions deliberately removed; no equivalent handoff in current source | Restore the pair, with the PCIe override and display node restricted to KPFE |
| Audio sleep | Board I²S release, LPASS macro PM clocks, forced SoundWire/macro/pinctrl suspend present | Retain preview code, including subsequent fixes |
| Gamepad MCU | #712 power-off path present | Retain preview code |
| Charging | Native percentage limiter and separate constant-current control | Add an opt-in manual 0x06 diagnostic; no automatic limiter or property-29 policy |

The optional CESTA pair is separate from the already-upstream PCIe changes.
Its historical removal is preserved in the provenance; neither additional
power savings nor stability on this preview is established by source checks.

## Manual charging

`qcom_battmgr.manual_charge_rate=1` enables the diagnostic at module load on
KPFE only. Default is off. Enabling it sends no charge-rate command and does
not itself disable a previously enabled firmware percentage limit.

In diagnostic mode:

- `charge_behaviour=inhibit-charge` sends opcode `0x06`, rate **0**.
- `charge_behaviour=auto` sends rate **100**, releasing the rate stop. This is
  a charging-rate command, not a target battery percentage.
- End threshold **100** sends native limit command `0x48` with enable **0**.
  Any target below 100 and all constant-current writes are rejected, so the
  native percentage/current controls cannot compete with this test.
- Stop checks a fresh property-24 reply and rejects an enabled native limiter.
- Readback is the last acknowledged command. It returns no data before the
  first command, after a failed charge-rate request or across a firmware
  service-generation change. It does not measure battery isolation or input
  power.
- No percentage worker, boot command, reconnect replay or service-recovery
  charging command is installed.

Before a hardware test, restore Normal mode in the previous charging policy,
disable its automatic service, then verify the active image, boot parameter,
available controls and firmware limit state. Persisted `/etc` configuration
can survive an image change; a different kernel alone does not establish
exclusive control. These target checks have not been performed.

The first sequence is active charging below the selected test level, explicit
stop, a measured hold, then explicit resume. Capture command acknowledgments,
battery status/current/voltage/health and external USB input through each
transition. An error ends the comparison; automatic retry/recovery is outside
this diagnostic. The firmware protocol has no request transaction ID, so the
opcode guard cannot distinguish a very late reply to an earlier request with
the same opcode. Reconnect, repeated sleep and service restart remain separate
hardware tests.

## Validation

- All **333** kernel and DTS patch files apply to a fresh Linux 7.2.6 tree
  with zero fuzz and every hunk accounted for.
- All **24** candidate-modified source/DTS files match the tree used for the
  compile checks.
- Chipone and Iris objects, qcom_battmgr, both CESTA objects and the KPFE DTB
  compile. Existing vendor Chipone warnings remain.
- Gamescope's affected files accept the carried fix after current Armada
  patches. A full Gamescope package build remains pending.
- Tests compile the actual manual-control C functions against a simulated
  GLINK transport. Stop/resume payloads, policy exclusion, unsupported modes,
  initial unknown state, wrong/malformed/error responses, timeout and service
  restart cases pass. These are software checks, not charging measurements.
- The local host lacks `pahole`, so its configuration omits BTF and
  `SCHED_CLASS_EXT`. The image builder installs `dwarves`; the full requested
  configuration, module link, image assembly and hardware validation remain
  pending. No source configuration was weakened to accommodate the host.

The Iris close-path refresh preserves preview's deferred decoder-work
shutdown. The CESTA PCIe match is narrowed to KPFE. Other carried touch and
recording behavior remains as in the recorded patches. No image build,
publication, deployment or device charging change has been performed.

Run the diagnostic software checks against a prepared kernel source tree:

```sh
python3 packages/kernel/tests/test-kpfe-manual-charge.py /path/to/linux/drivers/power/supply/qcom_battmgr.c
```

The kernel build script runs the same check before generating its configuration.

## Build workflow

Fork package pulls use registry authentication. Unchanged packages can reuse
official artifacts only under the exact package-input hash; resolved artifacts
are pinned by manifest digest. Changed kernel/Gamescope inputs build in the
fork. These build adaptations retain the previous fork workflow behavior from
`c23c8d3` and `30ef88c`; no older package or image baseline is substituted.

The fork image-build workflow is enabled and its `SIGNING_SECRET` is present.
Secret contents were not inspected. Registry availability and runner execution
remain build-time checks.
