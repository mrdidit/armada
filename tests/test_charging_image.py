# SPDX-License-Identifier: GPL-2.0-or-later
import importlib.util
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "charging_image", Path(__file__).resolve().parents[1] / "build_files/install-charging-policy.py")
image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(image)


class ImageChecks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name, content="content"):
        path = image.path_at(self.root, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def configurations(self):
        self.write("/etc/armada-charging/devices.json", json.dumps({
            "schema_version": 1,
            "devices": [{"compatible": "konkr,pocket-fit-elite", "backend": "kpfe-qcom-battmgr",
                         "implemented": True, "validated": False, "lifecycle_validated": False}],
        }))
        self.write("/etc/armada-charging/ownership.json", json.dumps({
            "schema_version": 1, "exclusive_control": False, "integration_ready": False,
            "review_reference": "", "integration": "kde-shared-policy-v1",
            "development": None, "files": {},
        }))
        self.write("/usr/lib/systemd/system/armada-charging.service")

    def inventory(self):
        before = image.Counter(image.BASE_PACKAGES)
        before[("unrelated", "0", "1.0", "1.fc44", "aarch64")] = 1
        after = image.Counter(item[2] for item in image.PACKAGES.values())
        after[("unrelated", "0", "1.0", "1.fc44", "aarch64")] = 1
        return before, after

    def test_snapshot_hashes_content_mode_and_symlink_without_following(self):
        source = self.write("/etc/settings", "first")
        self.write("/outside", "private")
        (self.root / "etc/link").symlink_to("../outside")
        first = image.snapshot(self.root, ("/etc",))
        self.assertNotIn("/outside", first)
        self.assertEqual(first["/etc/link"]["target"], "../outside")
        self.assertEqual(first["/etc/settings"]["uid"], os.getuid())
        source.write_text("other")
        second = image.snapshot(self.root, ("/etc",))
        self.assertNotEqual(first["/etc/settings"]["sha256"], second["/etc/settings"]["sha256"])
        source.chmod(0o600)
        third = image.snapshot(self.root, ("/etc",))
        self.assertNotEqual(second["/etc/settings"]["mode"], third["/etc/settings"]["mode"])

    def test_snapshot_records_extended_attributes(self):
        path = self.write("/etc/settings")
        try:
            os.setxattr(path, "user.charging-test", b"one")
        except OSError as error:
            self.skipTest(str(error))
        first = image.snapshot(self.root, ("/etc",))
        os.setxattr(path, "user.charging-test", b"two")
        second = image.snapshot(self.root, ("/etc",))
        self.assertNotEqual(first["/etc/settings"]["xattrs"], second["/etc/settings"]["xattrs"])

    def test_snapshot_missing_protected_path_is_recorded(self):
        self.assertEqual(image.snapshot(self.root, ("/boot",)), {"/boot": None})

    def hwdb_fixture(self):
        cache = self.write(image.HWDB_CACHE, "compiled cache")
        source = self.write("/usr/lib/udev/hwdb.d/test.hwdb", "test source")
        self.write(image.HWDB_GENERATOR, "generator")
        self.write("/usr/lib64/libc.so.6", "library")
        command = patch.object(image, "run", return_value=subprocess.CompletedProcess(
            [], 0, "libc.so.6 => /usr/lib64/libc.so.6 (0x1234)\n", ""))
        command.start()
        self.addCleanup(command.stop)
        return cache, source

    def test_hwdb_same_bytes_restore_original_mode_and_xattrs(self):
        cache, source = self.hwdb_fixture()
        try:
            os.setxattr(cache, "user.component", b"base")
            os.setxattr(source, "user.component", b"base")
        except OSError as error:
            self.skipTest(str(error))
        before = image.capture_hwdb(self.root)
        cache.unlink()
        cache.write_text("compiled cache")
        cache.chmod(0o600)
        os.setxattr(cache, "user.extra", b"new")
        os.removexattr(source, "user.component")
        result = image.restore_hwdb_metadata(before, self.root)
        self.assertTrue(result["metadata_restored"])
        self.assertEqual(image.entry(cache), before["cache"])
        self.assertEqual(cache.stat().st_mtime_ns, before["times"][1])

    def test_hwdb_changed_compiled_bytes_are_refused(self):
        cache, _ = self.hwdb_fixture()
        before = image.capture_hwdb(self.root)
        cache.write_text("different compiled bytes")
        with self.assertRaisesRegex(image.VerificationError, "cache bytes changed"):
            image.restore_hwdb_metadata(before, self.root)
        self.assertEqual(cache.read_text(), "different compiled bytes")

    def test_hwdb_changed_source_and_generator_are_refused(self):
        _, source = self.hwdb_fixture()
        for path in (source, self.root / image.HWDB_GENERATOR.lstrip("/"),
                     self.root / "usr/lib64/libc.so.6"):
            with self.subTest(path=path):
                original = path.read_text()
                before = image.capture_hwdb(self.root)
                path.write_text("changed")
                with self.assertRaises(image.VerificationError):
                    image.restore_hwdb_metadata(before, self.root)
                path.write_text(original)

    def test_hwdb_source_mode_change_is_refused(self):
        _, source = self.hwdb_fixture()
        before = image.capture_hwdb(self.root)
        source.chmod(0o600)
        with self.assertRaisesRegex(image.VerificationError, "sources changed"):
            image.restore_hwdb_metadata(before, self.root)

    def test_hwdb_source_link_target_contents_are_checked(self):
        _, source = self.hwdb_fixture()
        target = self.write("/source-target", "original")
        source.unlink()
        source.symlink_to(target)
        before = image.capture_hwdb(self.root)
        target.write_text("changed")
        with self.assertRaisesRegex(image.VerificationError, "sources changed"):
            image.restore_hwdb_metadata(before, self.root)

    def test_hwdb_missing_and_symlink_cache_are_refused(self):
        cache, _ = self.hwdb_fixture()
        before = image.capture_hwdb(self.root)
        cache.unlink()
        with self.assertRaisesRegex(image.VerificationError, "regular hwdb cache"):
            image.restore_hwdb_metadata(before, self.root)
        target = self.write("/cache-target", "compiled cache")
        cache.symlink_to(target)
        with self.assertRaisesRegex(image.VerificationError, "regular hwdb cache"):
            image.restore_hwdb_metadata(before, self.root)

    def test_hwdb_new_search_directory_is_refused(self):
        self.hwdb_fixture()
        before = image.capture_hwdb(self.root)
        self.write("/run/udev/hwdb.d/override.hwdb", "override")
        with self.assertRaisesRegex(image.VerificationError, "sources changed"):
            image.restore_hwdb_metadata(before, self.root)

    def test_only_exact_configuration_additions_are_allowed(self):
        self.write("/etc/existing")
        before = image.snapshot(self.root, ("/etc",))
        self.configurations()
        image.verify_snapshots(before, image.snapshot(self.root, ("/etc",)))

    def test_preserved_configuration_mutation_is_refused(self):
        original = self.write("/etc/existing")
        before = image.snapshot(self.root, ("/etc",))
        self.configurations()
        original.write_text("changed")
        with self.assertRaises(image.VerificationError):
            image.verify_snapshots(before, image.snapshot(self.root, ("/etc",)))

    def test_extra_configuration_and_missing_addition_are_refused(self):
        self.write("/etc/existing")
        before = image.snapshot(self.root, ("/etc",))
        self.configurations()
        extra = self.write("/etc/extra")
        with self.assertRaises(image.VerificationError):
            image.verify_snapshots(before, image.snapshot(self.root, ("/etc",)))
        extra.unlink()
        (self.root / "etc/armada-charging/devices.json").unlink()
        with self.assertRaises(image.VerificationError):
            image.verify_snapshots(before, image.snapshot(self.root, ("/etc",)))

    def test_enablement_snapshot_catches_symlinks_and_dependency_files(self):
        directory = self.root / "usr/lib/systemd/system"
        directory.mkdir(parents=True)
        first = image.enablement_snapshot(self.root)
        self.write("/usr/lib/systemd/system/armada-charging.service")
        self.assertEqual(first, image.enablement_snapshot(self.root))
        wants = directory / "multi-user.target.wants"
        wants.mkdir()
        (wants / "armada-charging.service").symlink_to("../armada-charging.service")
        self.assertNotEqual(first, image.enablement_snapshot(self.root))

    def test_exact_inventory_delta(self):
        image.verify_inventory(*self.inventory())

    def test_unrelated_package_change_is_refused(self):
        before, after = self.inventory()
        after[("extra", "0", "1", "1", "aarch64")] += 1
        with self.assertRaises(image.VerificationError):
            image.verify_inventory(before, after)

    def test_missing_replacement_or_duplicate_is_refused(self):
        before, after = self.inventory()
        after[image.PACKAGES["upower"][2]] = 0
        with self.assertRaises(image.VerificationError):
            image.verify_inventory(before, after)
        before, after = self.inventory()
        after[image.PACKAGES["upower"][2]] = 2
        with self.assertRaises(image.VerificationError):
            image.verify_inventory(before, after)

    def test_unreviewed_base_is_refused(self):
        before, _ = self.inventory()
        before[("powerdevil", "0", "6.7.4", "other", "aarch64")] = 1
        with self.assertRaises(image.VerificationError):
            image.verify_base_inventory(before)

    def test_inventory_parser_requires_all_identity_fields(self):
        self.assertEqual(image.parse_inventory("pkg\t0\t1\t2\tnoarch\n"),
                         image.Counter({("pkg", "0", "1", "2", "noarch"): 1}))
        for output in ("", "pkg\t1\t2\tnoarch", "pkg\tnone\t1\t2\tnoarch"):
            with self.subTest(output=output), self.assertRaises(image.VerificationError):
                image.parse_inventory(output)

    def test_disabled_candidate_passes(self):
        self.configurations()
        image.verify_disabled(self.root)

    def test_enrollment_or_persisted_state_is_refused(self):
        self.configurations()
        for name in ("/etc/armada-charging/managed.d/battery", "/var/lib/armada-charging/policy.json",
                     "/run/armada-charging/monitor.lock"):
            with self.subTest(name=name):
                path = self.write(name)
                with self.assertRaises(image.VerificationError):
                    image.verify_disabled(self.root)
                path.unlink()
                path.parent.rmdir()

    def test_ownership_or_development_enabling_is_refused(self):
        self.configurations()
        path = self.root / "etc/armada-charging/ownership.json"
        original = json.loads(path.read_text())
        for field, value in (("exclusive_control", True), ("integration_ready", True),
                             ("development", {"enabled": True}), ("exclusive_control", 0),
                             ("review_reference", "review"), ("schema_version", True)):
            with self.subTest(field=field, value=value):
                path.write_text(json.dumps({**original, field: value}))
                with self.assertRaises(image.VerificationError):
                    image.verify_disabled(self.root)

    def test_validation_enabling_and_integer_booleans_are_refused(self):
        self.configurations()
        path = self.root / "etc/armada-charging/devices.json"
        original = json.loads(path.read_text())
        for field, value in (("validated", True), ("lifecycle_validated", True), ("validated", 0)):
            with self.subTest(field=field):
                changed = json.loads(json.dumps(original))
                changed["devices"][0][field] = value
                path.write_text(json.dumps(changed))
                with self.assertRaises(image.VerificationError):
                    image.verify_disabled(self.root)

    def test_configuration_symlink_is_refused(self):
        self.configurations()
        path = self.root / "etc/armada-charging/devices.json"
        target = self.root / "devices.json"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaises(image.VerificationError):
            image.verify_disabled(self.root)

    def test_non_object_configuration_is_refused(self):
        self.configurations()
        self.write("/etc/armada-charging/devices.json", "[]")
        with self.assertRaises(image.VerificationError):
            image.verify_disabled(self.root)

    def test_service_enablement_or_alias_is_refused(self):
        self.configurations()
        alias = self.root / "usr/lib/systemd/system/other.service"
        alias.symlink_to("armada-charging.service")
        with self.assertRaises(image.VerificationError):
            image.verify_disabled(self.root)

    def test_preserved_rpm_config_difference_only(self):
        before = {"/etc/UPower/UPower.conf": {"sha256": "same"}}
        result = subprocess.CompletedProcess([], 1, "S.5....T.  c /etc/UPower/UPower.conf\n", "")
        self.assertEqual(image.verify_rpm_files(result, before, before), result.stdout.splitlines())
        for output in ("S.5....T.    /usr/libexec/upowerd\n", "missing   c /etc/UPower/UPower.conf\n"):
            with self.subTest(output=output), self.assertRaises(image.VerificationError):
                image.verify_rpm_files(subprocess.CompletedProcess([], 1, output, ""), before, before)
        with self.assertRaises(image.VerificationError):
            image.verify_rpm_files(result, before, {"/etc/UPower/UPower.conf": {"sha256": "changed"}})

    def test_empty_failed_rpm_verification_is_refused(self):
        with self.assertRaises(image.VerificationError):
            image.verify_rpm_files(subprocess.CompletedProcess([], 1, "", ""), {}, {})

    def test_build_environment_rejects_host_and_wrong_architecture(self):
        self.write("/.dockerenv", "")
        with patch.object(image.os, "geteuid", return_value=0), patch.object(image.platform, "machine", return_value="aarch64"):
            image.verify_environment(self.root)
            marker = self.write("/run/ostree-booted", "")
            with self.assertRaises(image.VerificationError):
                image.verify_environment(self.root)
            marker.unlink()
        with patch.object(image.platform, "machine", return_value="x86_64"):
            with self.assertRaises(image.VerificationError):
                image.verify_environment(self.root)

    def test_invalid_input_set_is_refused_before_rpm_query(self):
        with patch.object(image, "run") as command:
            with self.assertRaises(image.VerificationError):
                image.verify_inputs(self.root)
            command.assert_not_called()

    def test_invalid_input_checksum_is_refused_before_rpm_query(self):
        for filename, _, _ in image.PACKAGES.values():
            self.write(filename, "not the reviewed rpm")
        with patch.object(image, "run") as command:
            with self.assertRaises(image.VerificationError):
                image.verify_inputs(self.root)
            command.assert_not_called()

    def test_install_refuses_environment_before_any_package_command(self):
        with patch.object(image, "verify_environment", side_effect=image.VerificationError("not a container")), \
             patch.object(image, "run") as command:
            with self.assertRaises(image.VerificationError):
                image.install()
            command.assert_not_called()

    def mock_installation(self, stack, *, test_failure=False):
        before_packages, after_packages = self.inventory()
        inventory_text = lambda packages: "".join("\t".join(item) + "\n" for item in packages.elements())
        complete = lambda output="": subprocess.CompletedProcess([], 0, output, "")
        responses = [complete(inventory_text(before_packages))]
        responses += [image.VerificationError("test transaction refused")] if test_failure else [
            complete(), complete(), complete(), complete(inventory_text(after_packages)), complete()]
        command = stack.enter_context(patch.object(image, "run", side_effect=responses))
        for name in ("verify_environment", "verify_kernel", "verify_disabled"):
            stack.enter_context(patch.object(image, name))
        stack.enter_context(patch.object(image, "capture_hwdb", return_value={}))
        stack.enter_context(patch.object(image, "restore_hwdb_metadata", return_value={}))
        paths = [str(image.RPM_DIRECTORY / item[0]) for item in image.PACKAGES.values()]
        stack.enter_context(patch.object(image, "verify_inputs", return_value=paths))
        before = {"/etc/retained": {"sha256": "same"}}
        after = {**before, **{name: {} for name in image.NEW_CONFIG_PATHS}}
        stack.enter_context(patch.object(image, "snapshot", side_effect=[before, after]))
        stack.enter_context(patch.object(image, "enablement_snapshot", return_value={}))
        stack.enter_context(patch.object(image, "sha256", return_value="f" * 64))
        evidence = self.root / "report/image-verification.json"
        stack.enter_context(patch.object(image, "EVIDENCE_PATH", evidence))
        return command, paths, evidence

    def test_install_uses_test_then_exact_transaction_and_emits_evidence(self):
        with ExitStack() as stack:
            command, paths, evidence = self.mock_installation(stack)
            image.install()
            calls = [call.args[0] for call in command.call_args_list]
            self.assertEqual(calls, [
                ["rpm", "-qa", "--qf", image.QUERY_FORMAT],
                ["rpm", "-Uvh", "--test", *paths], ["rpm", "-Uvh", *paths],
                ["rpmdb", "--verifydb"], ["rpm", "-qa", "--qf", image.QUERY_FORMAT],
                ["rpm", "-V", *image.PACKAGES],
            ])
            report = json.loads(evidence.read_text())
            self.assertFalse(report["charging_enabled"])
            self.assertFalse(report["kernel_rebuilt"])
            self.assertEqual(report["package_build_id"], "35854292032")
            self.assertEqual(report["enablement_receipt"], "not-generated")

    def test_failed_test_transaction_never_installs_or_emits_evidence(self):
        with ExitStack() as stack:
            command, paths, evidence = self.mock_installation(stack, test_failure=True)
            with self.assertRaises(image.VerificationError):
                image.install()
            self.assertEqual(command.call_count, 2)
            self.assertEqual(command.call_args.args[0], ["rpm", "-Uvh", "--test", *paths])
            self.assertFalse(evidence.exists())


if __name__ == "__main__":
    unittest.main()
