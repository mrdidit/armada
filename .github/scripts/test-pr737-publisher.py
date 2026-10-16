#!/usr/bin/env python3
"""Offline provenance, archive and no-overwrite checks for the fork publisher."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("prepare", HERE / "prepare-pr737-artifact.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
spec = importlib.util.spec_from_file_location("oci_fixture", HERE / "test-hash-iris-oci-module.py")
oci_fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oci_fixture)


def fixture():
    values = dict(run_id=123, run_attempt=2, artifact_id=456, head_sha="a" * 40,
                  merge_sha="b" * 40, tree_sha="c" * 40, artifact_sha256="d" * 64,
                  base_sha="e" * 40, merge_tree_sha="9" * 40)
    run = dict(id=123, run_attempt=2, status="completed", conclusion="success",
               event="pull_request", path=".github/workflows/pr.yml", workflow_id=789,
               repository={"full_name": prepare.UPSTREAM},
               head_repository={"full_name": prepare.FORK}, head_branch=prepare.BRANCH,
               head_sha=values["head_sha"], run_started_at="2026-10-15T20:00:00Z",
               updated_at="2026-10-15T21:00:00Z")
    workflow = dict(id=789, path=".github/workflows/pr.yml")
    pr = dict(number=737, state="open", merge_commit_sha=values["merge_sha"],
              head={"repo": {"full_name": prepare.FORK}, "ref": prepare.BRANCH,
                    "sha": values["head_sha"]},
              base={"repo": {"full_name": prepare.UPSTREAM}, "ref": "main", "sha": "e" * 40})
    head = dict(sha=values["head_sha"], tree={"sha": values["tree_sha"]})
    merge = dict(sha=values["merge_sha"], tree={"sha": values["merge_tree_sha"]},
                 parents=[{"sha": values["base_sha"]}, {"sha": values["head_sha"]}])
    artifact = dict(id=456, name=prepare.ARTIFACT_NAME, expired=False,
                    digest="sha256:" + values["artifact_sha256"], size_in_bytes=100,
                    created_at="2026-10-15T20:30:00Z",
                    workflow_run={"id": 123, "head_sha": values["head_sha"],
                                  "head_branch": prepare.BRANCH})
    jobs = {"total_count": 1, "jobs": [{"name": "Container image", "run_id": 123,
             "run_attempt": 2, "status": "completed", "conclusion": "success", "steps": [{
                 "name": "Upload container image", "status": "completed", "conclusion": "success",
                 "started_at": "2026-10-15T20:29:00Z", "completed_at": "2026-10-15T20:30:00Z"}]}]}
    return [values, run, copy.deepcopy(run), workflow, pr, head, merge, artifact, jobs]


class ProvenanceTests(unittest.TestCase):
    def test_exact_successful_source_passes(self):
        prepare.validate_metadata(*fixture())

    def test_upstream_advance_keeps_original_build_identity(self):
        args = fixture()
        args[4]["base"]["sha"] = "2" * 40
        args[4]["merge_commit_sha"] = "3" * 40
        prepare.validate_metadata(*args)
        for field in ("base_sha", "merge_tree_sha", "merge_sha", "tree_sha"):
            changed = copy.deepcopy(args)
            changed[0][field] = "0" * 40
            with self.subTest(field=field), self.assertRaises(ValueError):
                prepare.validate_metadata(*changed)

    def test_rewritten_current_head_requires_the_original_tree(self):
        args = fixture()
        args[4]["head"]["sha"] = "f" * 40
        args[4]["merge_commit_sha"] = "1" * 40
        current = {"sha": "f" * 40, "tree": {"sha": args[0]["tree_sha"]}}
        prepare.validate_metadata(*args, current)
        for invalid in (None, {"sha": "2" * 40, "tree": current["tree"]},
                        {"sha": current["sha"], "tree": {"sha": "2" * 40}}):
            with self.subTest(current=invalid), self.assertRaises(ValueError):
                prepare.validate_metadata(*args, invalid)

    def test_rewritten_head_does_not_relax_original_artifact_provenance(self):
        for index, path, value in (
                (1, ("head_sha",), "f" * 40), (1, ("run_attempt",), 3),
                (1, ("conclusion",), "failure"), (2, ("run_attempt",), 3),
                (0, ("base_sha",), "1" * 40),
                (0, ("merge_tree_sha",), "1" * 40),
                (5, ("sha",), "f" * 40), (5, ("tree", "sha"), "1" * 40),
                (6, ("sha",), "1" * 40), (6, ("tree", "sha"), "1" * 40),
                (7, ("id",), 999), (7, ("workflow_run", "head_sha"), "f" * 40),
                (7, ("digest",), "sha256:" + "1" * 64),
                (7, ("created_at",), "2026-10-15T20:20:00Z")):
            with self.subTest(index=index, path=path):
                args = fixture()
                args[4]["head"]["sha"] = "f" * 40
                args[4]["merge_commit_sha"] = "1" * 40
                current = {"sha": "f" * 40, "tree": {"sha": args[0]["tree_sha"]}}
                target = args[index]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    prepare.validate_metadata(*args, current)

    def test_current_commit_is_fetched_by_its_exact_validated_sha(self):
        args = fixture()
        with mock.patch.object(prepare, "api") as api:
            self.assertEqual(prepare.current_head_commit(args[4], args[5]), args[5])
            api.assert_not_called()
            args[4]["head"]["sha"] = "f" * 40
            prepare.current_head_commit(args[4], args[5])
            api.assert_called_once_with("git/commits/" + "f" * 40)
            args[4]["head"]["sha"] = "../../unrelated"
            with self.assertRaises(ValueError):
                prepare.current_head_commit(args[4], args[5])

    def test_metadata_substitution_and_failed_runs_are_rejected(self):
        mutations = [
            (1, ("repository", "full_name"), "unrelated/armada"),
            (1, ("conclusion",), "failure"), (1, ("status",), "in_progress"),
            (1, ("run_attempt",), 3), (2, ("run_attempt",), 1),
            (1, ("event",), "workflow_dispatch"),
            (1, ("path",), ".github/workflows/build.yml"),
            (1, ("head_repository", "full_name"), "another/armada"),
            (1, ("head_sha",), "0" * 40), (3, ("id",), 111),
            (4, ("number",), 738), (4, ("state",), "closed"),
            (4, ("head", "sha"), "0" * 40),
            (0, ("base_sha",), "0" * 40),
            (0, ("merge_tree_sha",), "0" * 40),
            (5, ("tree", "sha"), "0" * 40),
            (6, ("parents",), [{"sha": "0" * 40}]),
            (6, ("tree", "sha"), "0" * 40),
            (7, ("id",), 457), (7, ("name",), "armada-disk-pr737"),
            (7, ("expired",), True), (7, ("digest",), "sha256:" + "0" * 64),
            (7, ("workflow_run", "id"), 999),
            (7, ("created_at",), "2026-10-15T19:00:00Z"),
            (7, ("created_at",), "2026-10-15T20:20:00Z"),
            (7, ("size_in_bytes",), 0),
            (8, ("total_count",), 2),
        ]
        for index, path, value in mutations:
            with self.subTest(index=index, path=path):
                args = fixture()
                target = args[index]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    prepare.validate_metadata(*args)

    def test_inputs_reject_shell_text_and_bad_ids(self):
        env = {"PR737_" + key.upper(): str(value) for key, value in fixture()[0].items()}
        self.assertEqual(prepare.inputs(env), fixture()[0])
        for key, value in (("PR737_RUN_ID", "123; echo bad"), ("PR737_RUN_ID", "0"),
                           ("PR737_HEAD_SHA", "$(id)"), ("PR737_BASE_SHA", "../base"),
                           ("PR737_MERGE_TREE_SHA", ""), ("PR737_ARTIFACT_SHA256", "F" * 64)):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                prepare.inputs({**env, key: value})


class ArchiveTests(unittest.TestCase):
    def archive(self, directory, members):
        path = Path(directory) / "artifact.zip"
        with zipfile.ZipFile(path, "w") as zipped:
            for name in members:
                zipped.writestr(name, b"data, never executable")
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_only_expected_file_is_extracted(self):
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self.archive(directory, [prepare.ARCHIVE_NAME])
            result = prepare.verify_zip(path, digest)
            self.assertEqual(result.read_bytes(), b"data, never executable")

    def test_corruption_extra_members_traversal_and_symlink_rejected(self):
        link = zipfile.ZipInfo(prepare.ARCHIVE_NAME)
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        for members in (["../armada-pr-737.tar"], [prepare.ARCHIVE_NAME, "other"], [link]):
            with self.subTest(members=members), tempfile.TemporaryDirectory() as directory:
                path, digest = self.archive(directory, members)
                with self.assertRaises(ValueError):
                    prepare.verify_zip(path, digest)
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self.archive(directory, [prepare.ARCHIVE_NAME])
            with self.assertRaises(ValueError):
                prepare.verify_zip(path, "0" * 64)


class ImageTests(unittest.TestCase):
    def fixture(self):
        config = {"architecture": "arm64", "os": "linux", "config": {
            "Cmd": ["/sbin/init"], "Labels": {
                "org.opencontainers.image.revision": "b" * 40,
                "org.opencontainers.image.version": "20261015.bbbbbbb",
                "containers.bootc": "1", "ostree.bootable": "true"}}}
        blob = {"digest": "sha256:" + "f" * 64, "size": 100}
        manifest = {"schemaVersion": 2, "config": blob.copy(),
                    "layers": [blob.copy(), blob.copy()]}
        return config, manifest

    def test_expected_bootc_image_passes(self):
        prepare.validate_oci(fixture()[0], *self.fixture())

    def test_incompatible_source_metadata_or_external_blobs_rejected(self):
        mutations = [
            (0, ("architecture",), "amd64"), (0, ("os",), "windows"),
            (0, ("config", "Cmd"), ["/bin/sh"]),
            (0, ("config", "Labels", "org.opencontainers.image.revision"), "a" * 40),
            (0, ("config", "Labels", "containers.bootc"), "0"),
            (0, ("config", "Labels", "ostree.commit"), "stale"),
            (1, ("annotations",), {"ostree.commit": "stale"}),
            (1, ("layers",), []),
            (1, ("config", "urls"), ["https://untrusted.invalid/blob"]),
        ]
        for index, path, value in mutations:
            with self.subTest(path=path):
                args = self.fixture()
                target = args[index]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(ValueError):
                    prepare.validate_oci(fixture()[0], *args)


class PreparationTests(unittest.TestCase):
    def simulate(self, *, final_tree_changed=False, corrupt_module=False):
        args = fixture()
        values, run, attempt, workflow, pr, head, merge, artifact, jobs = args
        pr["head"]["sha"] = "f" * 40
        pr["merge_commit_sha"] = "1" * 40
        current = {"sha": "f" * 40, "tree": {"sha": values["tree_sha"]}}
        metadata = {"actions/runs/123": run, "actions/runs/123/attempts/2": attempt,
                    "actions/workflows/789": workflow, "pulls/737": pr,
                    "git/commits/" + values["head_sha"]: head,
                    "git/commits/" + values["merge_sha"]: merge,
                    "git/commits/" + current["sha"]: current,
                    "actions/artifacts/456": artifact,
                    "actions/runs/123/attempts/2/jobs?per_page=100": jobs}
        current_reads = 0
        def api(path):
            nonlocal current_reads
            result = copy.deepcopy(metadata[path])
            if path == "git/commits/" + current["sha"]:
                current_reads += 1
                if final_tree_changed and current_reads == 2:
                    result["tree"]["sha"] = "2" * 40
            return result

        actual_command, actual_run = prepare.command, subprocess.run
        def run_command(command, **kwargs):
            if command[:2] == ["gh", "api"]:
                self.assertEqual(command[2], "repos/armada-os/armada/actions/artifacts/456/zip")
                kwargs["stdout"].write(b"fake ZIP; extraction mocked below")
                return subprocess.CompletedProcess(command, 0)
            return actual_run(command, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / prepare.ARCHIVE_NAME
            with mock.patch.object(oci_fixture, "REVISION", values["merge_sha"]):
                digest = oci_fixture.make_archive(archive,
                    [[(oci_fixture.MODULE + ".xz", b"original module bytes"),
                      (oci_fixture.MOD.GAMESCOPE, b"original gamescope bytes")]],
                    compressed=True, corrupt=corrupt_module)
            config, manifest = ImageTests().fixture()
            def command(command):
                if command[:2] == ["skopeo", "inspect"]:
                    if command[2] == "--config":
                        return json.dumps(config).encode()
                    if command[2] == "--raw":
                        return json.dumps(manifest).encode()
                    return digest.encode()
                return actual_command(command)

            output = root / "prepared"
            env = {"PR737_" + key.upper(): str(value) for key, value in values.items()}
            with mock.patch.dict(os.environ, env), \
                    mock.patch.object(prepare.sys, "argv", ["prepare", "--output", str(output)]), \
                    mock.patch.object(prepare, "api", side_effect=api), \
                    mock.patch.object(prepare, "command", side_effect=command), \
                    mock.patch.object(prepare.subprocess, "run", side_effect=run_command), \
                    mock.patch.object(prepare, "verify_zip", return_value=archive):
                if final_tree_changed:
                    with self.assertRaisesRegex(ValueError, "Current PR head"):
                        prepare.main()
                elif corrupt_module:
                    with self.assertRaises(subprocess.CalledProcessError):
                        prepare.main()
                else:
                    prepare.main()
            evidence = output / "evidence"
            return {path.name: json.loads(path.read_text()) for path in evidence.glob("*.json")}

    def test_module_evidence_and_rewritten_head_keep_original_image_provenance(self):
        files = self.simulate()
        result = files["publication.json"]
        original = fixture()[0]
        for key, value in original.items():
            self.assertEqual(result[key], value)
        self.assertEqual(result["image_tag"], "pr737-build-123-2-aaaaaaa")
        self.assertEqual(result["current_pr"]["head_sha"], "f" * 40)
        self.assertFalse(result["current_pr"]["head_matches_build"])
        module = files["iris-module.json"]
        self.assertEqual(module["manifest_digest"], result["manifest_digest"])
        self.assertEqual(module["image_revision"], original["merge_sha"])
        self.assertEqual(module["module"], result["iris_module"])
        self.assertEqual(module["module"]["sha256"], hashlib.sha256(b"original module bytes").hexdigest())
        self.assertEqual(module["gamescope"], result["gamescope"])
        self.assertEqual(result["gamescope"]["sha256"],
                         hashlib.sha256(b"original gamescope bytes").hexdigest())
        self.assertFalse(module["device_observation_used"])
        self.assertIn("upstream-final-current-head.json", files)

    def test_source_tree_change_during_inspection_stops_before_publication(self):
        files = self.simulate(final_tree_changed=True)
        self.assertIn("iris-module.json", files)
        self.assertNotIn("publication.json", files)

    def test_invalid_module_archive_stops_before_publication(self):
        files = self.simulate(corrupt_module=True)
        self.assertNotIn("iris-module.json", files)
        self.assertNotIn("publication.json", files)
        self.assertIn("image-manifest.json", files)


class PublicationTests(unittest.TestCase):
    def simulate(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "pr737"
            evidence = output / "evidence"
            evidence.mkdir(parents=True)
            (root / "expected-public.der").write_bytes(b"DER")
            (output / prepare.ARCHIVE_NAME).write_bytes(b"opaque archive")
            tag = "pr737-build-123-2-aaaaaaa"
            digest = "sha256:" + "f" * 64
            provenance = dict(oci_archive=str(output / prepare.ARCHIVE_NAME),
                              image_repository=prepare.IMAGE, image_tag=tag,
                              manifest_digest=digest, source_tree_verified=True,
                              upstream_run_conclusion="success", published=False)
            (evidence / "publication.json").write_text(json.dumps(provenance))
            binary = root / "bin"
            binary.mkdir()
            stub = binary / "tool.py"
            stub.write_text('''#!/usr/bin/env python3
import json, os
from pathlib import Path
import sys
name = Path(sys.argv[0]).name
args = sys.argv[1:]
mode = os.environ['TEST_MODE']
with open(os.environ['TEST_LOG'], 'a') as log:
    log.write(json.dumps([name, *args]) + '\\n')
if name == 'skopeo':
    if args[0] == 'inspect':
        wrong = ((mode == 'source-mismatch' and args[-1].startswith('oci-archive:')) or
                 (mode == 'existing-different' and args[-1].startswith('docker://')))
        print('sha256:' + ('0' if wrong else 'f') * 64)
    elif args[0] == 'list-tags':
        if mode == 'registry-error': sys.exit(2)
        print(json.dumps({'Tags': ['pr737-build-123-2-aaaaaaa'] if mode in ('existing-tag', 'existing-different') else ['known-good']}))
elif name == 'openssl':
    sys.stdout.buffer.write(b'WRONG' if mode == 'wrong-key' else b'DER')
elif name == 'cosign':
    if args[0] == 'import-key-pair':
        prefix = args[args.index('--output-key-prefix') + 1]
        Path(prefix + '.key').write_text('fake key')
        Path(prefix + '.pub').write_text('fake public key')
    elif args[0] == 'verify':
        print(json.dumps([{'critical': {'image': {'docker-manifest-digest': 'sha256:' + 'f' * 64}, 'identity': {'docker-reference': 'ghcr.io/mrdidit/armada'}}}]))
    elif args[0] == 'sign' and mode == 'signing-failed':
        sys.exit(2)
''')
            stub.chmod(0o755)
            for name in ("skopeo", "cosign", "openssl"):
                (binary / name).symlink_to(stub)
            log = root / "calls.jsonl"
            env = {**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"],
                   "GITHUB_REPOSITORY": prepare.FORK,
                   "GITHUB_REF": "refs/heads/test-pr737-artifact-publisher-20261015",
                   "GITHUB_ACTOR": "test", "GITHUB_STEP_SUMMARY": str(root / "summary"),
                   "RUNNER_TEMP": directory, "SIGNING_SECRET": "fake key",
                   "REGISTRY_TOKEN": "fake token", "COSIGN_PASSWORD": "",
                   "TEST_LOG": str(log), "TEST_MODE": mode}
            result = subprocess.run(["bash", str(HERE / "publish-pr737-artifact.sh"), str(output)],
                                    env=env, capture_output=True, text=True)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            final = json.loads((evidence / "publication.json").read_text())
            self.assertEqual(list(root.glob("pr737-signing.*")), [], "Temporary key files remained")
            return result, calls, final

    def test_success_preserves_digest_and_signs_unique_target(self):
        result, calls, final = self.simulate("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        copies = [call for call in calls if call[:2] == ["skopeo", "copy"]]
        self.assertEqual(len(copies), 1)
        self.assertIn("--preserve-digests", copies[0])
        self.assertEqual(copies[0][-1], "docker://ghcr.io/mrdidit/armada:pr737-build-123-2-aaaaaaa")
        signs = [call for call in calls if call[:2] == ["cosign", "sign"]]
        self.assertEqual(signs[0][-1], "ghcr.io/mrdidit/armada@sha256:" + "f" * 64)
        self.assertTrue(final["published"] and final["signature_verified"])

    def test_conflicting_tag_registry_error_bad_source_and_wrong_key_never_publish(self):
        for mode in ("existing-different", "registry-error", "source-mismatch", "wrong-key"):
            with self.subTest(mode=mode):
                result, calls, final = self.simulate(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call[:2] == ["skopeo", "copy"] for call in calls))
                self.assertFalse(final["published"])

    def test_matching_tag_can_be_signed_without_any_tag_write(self):
        result, calls, final = self.simulate("existing-tag")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call[:2] == ["skopeo", "copy"] for call in calls))
        self.assertTrue(final["reused_matching_tag"] and final["published"])

    def test_signing_failure_records_the_already_pushed_image(self):
        result, calls, final = self.simulate("signing-failed")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(final["image_pushed"])
        self.assertFalse(final["signature_verified"] or final["published"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
