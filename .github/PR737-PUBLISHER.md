# PR 737 artifact publisher

This fork-only branch publishes the exact container image produced by the
upstream PR 737 workflow. It does not rebuild the image, run files from it or
add publication machinery to the upstream PR. The registered `build.yml`
entry point is used because a new workflow on a non-default branch may not
be registered for dispatch.

The publisher accepts only a successful, completed `armada-os/armada` PR
workflow run for `mrdidit/armada:feat/kpfe-steam-recording`. The PR must remain
open on the specified fork branch. The original build head and synthetic
merge must have the expected Git tree. A rewritten current head is accepted
only after fetching that exact commit and verifying the same tree, with the
original merge base unchanged. This does not relabel the artifact: run,
attempt, build head, merge, image revision and tag remain pinned to the
original successful build.

The artifact must be `armada-container-pr737`, with the supplied immutable
artifact ID and ZIP SHA256. Its creation timestamp must fall within the
successful `Upload container image` step of the specified run attempt. This
prevents an artifact retained from an earlier attempt from being attributed
to a later successful attempt.

## Prerequisites

- Push this branch only to `mrdidit/armada` as
  `test-pr737-artifact-publisher-20261015`.
- The existing `SIGNING_SECRET` must remain the fork PEM private key matching
  `.github/keys/pr737-publisher.pub`. No new secret is required.
- GitHub Actions must be enabled, and the workflow token must be allowed to
  read the public upstream Actions artifact and write the existing fork GHCR
  package. Cross-repository artifact access with the fork workflow token has
  not yet been verified. Permission failure stops before image publication;
  the workflow does not silently introduce a personal token.
- Wait for the entire selected upstream PR run to complete successfully.
  Partial/cancelled runs are rejected even if an artifact exists.

## Collect inputs

Read the selected run and attempt, PR 737, its Git head and merge commits,
and artifact metadata. Do not substitute the publisher branch commit for the
source SHA. The image source is the upstream synthetic PR merge commit.

```sh
gh api repos/armada-os/armada/pulls/737
gh api repos/armada-os/armada/actions/runs/RUN_ID
gh api repos/armada-os/armada/actions/runs/RUN_ID/attempts/ATTEMPT
gh api repos/armada-os/armada/actions/runs/RUN_ID/artifacts
gh api repos/armada-os/armada/git/commits/HEAD_SHA
gh api repos/armada-os/armada/git/commits/MERGE_SHA
gh api repos/armada-os/armada/actions/artifacts/ARTIFACT_ID
```

Create a JSON file containing the exact values. `artifact_sha256` is the
artifact API `digest` without its `sha256:` prefix. All commit/tree SHAs are
the full 40 hexadecimal characters; all input values are JSON strings.

```json
{
  "ref": "test-pr737-artifact-publisher-20261015",
  "inputs": {
    "upstream_run_id": "RUN_ID",
    "upstream_run_attempt": "ATTEMPT",
    "expected_head_sha": "HEAD_SHA",
    "expected_merge_sha": "MERGE_SHA",
    "expected_tree_sha": "TREE_SHA",
    "artifact_id": "ARTIFACT_ID",
    "artifact_sha256": "ARTIFACT_ZIP_SHA256"
  }
}
```

Dispatch the already registered workflow at this dedicated branch:

```sh
gh api --method POST repos/mrdidit/armada/actions/workflows/build.yml/dispatches --input publisher-dispatch.json
```

The selected run and current PR metadata are checked again after download and
module inspection, before handing the archive to the publishing step.

## Publication and recovery

The image is copied with its OCI digest preserved to:

```text
ghcr.io/mrdidit/armada:pr737-build-RUN_ID-ATTEMPT-SHORT_HEAD
```

Existing release and test tags are untouched. If this unique tag already
exists with another digest, publication fails. If a previous attempt pushed
the exact same digest but signing failed, rerunning can finish signing that
image without copying it or writing the tag again. Registry lookup errors
fail instead of being treated as evidence that a tag is absent.

The existing PEM key is imported into Cosign's key format, its public identity
is checked, and the immutable image digest is signed. Signature verification
requires both the expected digest and `ghcr.io/mrdidit/armada` identity. Key
material is temporary and is not included in logs or evidence artifacts.

The evidence artifact records upstream run, attempt, upload job, source
head/merge/tree, artifact ZIP hash, image manifest/config, immutable image
digest and verified signature. Current PR head evidence is recorded separately
from the original build provenance.

`iris-module.json` records the installed `qcom-iris.ko`, `.ko.xz` or `.ko.zst`
file checksum directly from the pinned OCI archive. The reader verifies every
layer blob and uncompressed content digest, applies relevant OCI whiteouts,
and hashes the final stored module bytes. It does not execute the image,
extract its filesystem or use a checksum observed on the device. Raw and gzip
layers are supported; unsupported compression, ambiguous aliases, relevant
links and malformed layers stop publication without accepting a module hash.

`image_pushed` is recorded before signing;
`published` becomes true only after signature verification. A completed
publication still requires boot and recording/playback validation on hardware.

## Local checks

```sh
python3 .github/scripts/test-pr737-publisher.py
python3 .github/scripts/test-hash-iris-oci-module.py
bash -n .github/scripts/publish-pr737-artifact.sh
git diff --check
```

The offline tests cover source substitution, failed or different attempts,
artifact replacement, ZIP traversal/symlinks, incompatible image metadata,
registry failure, conflicting tags, signing failure and exact-digest recovery.
They also cover same-tree history rewrites without provenance substitution,
changes during inspection, module evidence generation and OCI layer handling.
They do not prove live token access or execute an image publication.
