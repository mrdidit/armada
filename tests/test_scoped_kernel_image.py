# SPDX-License-Identifier: GPL-2.0-or-later
from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "scoped_kernel_image", Path(__file__).resolve().parents[1] / "build_files/install-scoped-kernel.py")
image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(image)


class ScopedKernelChecks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, name, data=b"content"):
        path = image.policy.path_at(self.root, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def member(self, name=None, kind=tarfile.REGTYPE):
        member = tarfile.TarInfo(name or image.PREFIX + "vmlinuz")
        member.type = kind
        member.size = 4 if kind == tarfile.REGTYPE else 0
        member.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
        return member

    def inventory(self):
        files = {f"kernel/test/module{number}.ko": "module" for number in range(1618)}
        files.update({f"dtb/qcom/board{number}.dtb": "dtb" for number in range(24)})
        files.update(image.PINNED_FILES)
        return files

    def listing(self, *modules):
        return "\n".join(f"-rw-r--r-- 1 root root 123 Jan 1 00:00 {name}"
                         for name in (*image.BOOT_HELPERS, *modules))

    def test_success_inventory_has_exact_counts_and_pins(self):
        result = image.validate_inventory(self.inventory())
        self.assertEqual(result, {"modules": 1619, "dtbs": 25, "files": 1645})

    def test_missing_extra_and_altered_components_fail(self):
        changes = [lambda files: files.pop(image.MODULE),
                   lambda files: files.update({"kernel/extra.ko": "extra"}),
                   lambda files: files.update({"dtb/qcom/extra.dtb": "extra"}),
                   lambda files: files.update({"vmlinuz": "wrong"}),
                   lambda files: files.update({"kernel": "collision"}),
                   lambda files: files.update({"kernel/../escape": "escape"})]
        for change in changes:
            with self.subTest(change=change):
                files = self.inventory()
                change(files)
                with self.assertRaises(image.VerificationError):
                    image.validate_inventory(files)

    def test_unsafe_archive_paths_fail(self):
        for name in ("/etc/passwd", "../escape", image.PREFIX + "../escape",
                     image.PREFIX + "./file", image.PREFIX + "kernel//file", image.PREFIX + "bad\nname",
                     "lib/modules/7.2.4/vmlinuz", "lib/modules/7.2.3-extra/vmlinuz",
                     image.PREFIX + "initramfs.img", image.PREFIX + "KERNEL", "."):
            with self.subTest(name=name), self.assertRaises(image.VerificationError):
                image.validate_member(self.member(name), set())

    def test_links_and_special_members_fail(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.GNUTYPE_SPARSE):
            with self.subTest(kind=kind), self.assertRaises(image.VerificationError):
                image.validate_member(self.member(kind=kind), set())

    def test_owner_special_mode_empty_sparse_and_duplicate_fail(self):
        for attribute, value in (("uid", 1), ("gid", 1), ("mode", 0o4644), ("size", 0), ("sparse", [])):
            member = self.member()
            setattr(member, attribute, value)
            with self.subTest(attribute=attribute), self.assertRaises(image.VerificationError):
                image.validate_member(member, set())
        member = self.member()
        seen = set()
        image.validate_member(member, seen)
        with self.assertRaisesRegex(image.VerificationError, "Duplicate"):
            image.validate_member(member, seen)

    def test_only_release_payload_and_directory_ancestors_allowed(self):
        for name in ("lib", "lib/modules", image.PREFIX.rstrip("/")):
            self.assertIsNone(image.validate_member(self.member(name, tarfile.DIRTYPE), set()))
            with self.assertRaises(image.VerificationError):
                image.validate_member(self.member(name), set())
        self.assertEqual(image.validate_member(self.member(), set()), "vmlinuz")

    def test_sidecar_cannot_repin_changed_archive(self):
        archive = self.write("/archive.tar.zst", b"reviewed")
        sidecar = Path(str(archive) + ".sha256")
        digest = hashlib.sha256(b"reviewed").hexdigest()
        with patch.object(image, "ARCHIVE_SHA256", digest):
            sidecar.write_text(f"{digest}  {archive.name}\n")
            image.check_archive_pin(archive)
            archive.write_bytes(b"changed")
            sidecar.write_text(f"{hashlib.sha256(b'changed').hexdigest()}  {archive.name}\n")
            with self.assertRaises(image.VerificationError):
                image.check_archive_pin(archive)

    def test_archive_and_sidecar_symlinks_fail(self):
        archive = self.write("/archive", b"reviewed")
        linked = self.root / "linked"
        linked.symlink_to(archive)
        with self.assertRaisesRegex(image.VerificationError, "regular file"):
            image.check_archive_pin(linked)
        Path(str(archive) + ".sha256").symlink_to(archive)
        with self.assertRaisesRegex(image.VerificationError, "regular file"):
            image.check_archive_pin(archive)

    @contextmanager
    def archive(self, files):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as package:
            for name, content in files.items():
                member = self.member(image.PREFIX + name)
                member.size = len(content)
                package.addfile(member, io.BytesIO(content))
        data.seek(0)
        with tarfile.open(fileobj=data, mode="r|") as package:
            yield package

    def test_extract_matches_manifest_and_replaces_only_target(self):
        old = self.write(image.TARGET + "/old-module.ko", b"old")
        self.write("/usr/lib/firmware/retained", b"firmware")
        payload = {"vmlinuz": b"new-kernel", image.MODULE: b"new-module"}
        files = {name: hashlib.sha256(data).hexdigest() for name, data in payload.items()}
        before = image.policy.snapshot(self.root, ("/usr/lib/modules", "/usr/lib/firmware"))
        with patch.object(image, "package_stream", side_effect=lambda _: self.archive(payload)):
            image.replace_tree(Path("unused"), files, self.root)
        self.assertFalse(old.exists())
        self.assertEqual(image.policy.path_at(self.root, image.TARGET + "/vmlinuz").read_bytes(), b"new-kernel")
        self.assertEqual({path.name for path in old.parent.parent.iterdir()}, {image.RELEASE})
        image.verify_protected_delta(before, image.policy.snapshot(self.root, ("/usr/lib/modules", "/usr/lib/firmware")))

    def test_failed_extraction_preserves_original_target(self):
        old = self.write(image.TARGET + "/old-module.ko", b"old")
        with patch.object(image, "package_stream", side_effect=lambda _: self.archive({"vmlinuz": b"bad"})):
            with self.assertRaises(image.VerificationError):
                image.replace_tree(Path("unused"), {"vmlinuz": "wrong"}, self.root)
        self.assertEqual(old.read_bytes(), b"old")
        self.assertEqual({path.name for path in old.parent.parent.iterdir()}, {image.RELEASE})

    def test_overlay_exdev_copies_backup_with_symlinks_before_removing_exact_target(self):
        old = self.write(image.TARGET + "/old-module.ko", b"old")
        outside = self.write("/outside", b"untouched")
        (old.parent / "link").symlink_to(outside)
        original_rename, original_copytree = Path.rename, image.shutil.copytree
        def rename(path, destination):
            if path == old.parent:
                raise OSError(errno.EXDEV, "overlay lower directory")
            return original_rename(path, destination)
        def backup(source, destination, **kwargs):
            self.assertEqual(source, old.parent)
            self.assertEqual(kwargs, {"symlinks": True})
            result = original_copytree(source, destination, **kwargs)
            self.assertEqual((destination / "old-module.ko").read_bytes(), b"old")
            self.assertTrue((destination / "link").is_symlink())
            self.assertTrue(old.exists())
            return result
        payload = {"vmlinuz": b"new"}
        with patch.object(image, "package_stream", side_effect=lambda _: self.archive(payload)), \
                patch.object(Path, "rename", rename), patch.object(image.shutil, "copytree", side_effect=backup) as copied:
            image.replace_tree(Path("unused"), {"vmlinuz": hashlib.sha256(b"new").hexdigest()}, self.root)
            copied.assert_called_once()
        self.assertFalse(old.exists())
        self.assertEqual((old.parent / "vmlinuz").read_bytes(), b"new")
        self.assertEqual(outside.read_bytes(), b"untouched")
        self.assertEqual({path.name for path in old.parent.parent.iterdir()}, {image.RELEASE})

    def test_non_exdev_rename_failure_does_not_copy_or_remove_old_target(self):
        old = self.write(image.TARGET + "/old-module.ko", b"old")
        with patch.object(image, "package_stream", side_effect=lambda _: self.archive({"vmlinuz": b"new"})), \
                patch.object(Path, "rename", side_effect=PermissionError(errno.EACCES, "denied")), \
                patch.object(image.shutil, "copytree") as copied:
            with self.assertRaises(PermissionError):
                image.replace_tree(Path("unused"), {"vmlinuz": hashlib.sha256(b"new").hexdigest()}, self.root)
            copied.assert_not_called()
        self.assertEqual(old.read_bytes(), b"old")
        self.assertEqual({path.name for path in old.parent.parent.iterdir()}, {image.RELEASE})

    def test_exdev_failed_backup_keeps_original_tree(self):
        old = self.write(image.TARGET + "/old-module.ko", b"old")
        def failed_backup(source, destination, **kwargs):
            destination.mkdir()
            (destination / "partial").write_bytes(b"partial")
            raise OSError(errno.ENOSPC, "backup full")
        with patch.object(image, "package_stream", side_effect=lambda _: self.archive({"vmlinuz": b"new"})), \
                patch.object(Path, "rename", side_effect=OSError(errno.EXDEV, "overlay lower directory")), \
                patch.object(image.shutil, "copytree", side_effect=failed_backup):
            with self.assertRaisesRegex(OSError, "backup full"):
                image.replace_tree(Path("unused"), {"vmlinuz": hashlib.sha256(b"new").hexdigest()}, self.root)
        self.assertEqual(old.read_bytes(), b"old")
        self.assertEqual({path.name for path in old.parent.parent.iterdir()}, {image.RELEASE})

    def test_exdev_backup_is_restored_if_replacement_rename_fails(self):
        old = self.write(image.TARGET + "/old-module.ko", b"old")
        original_rename = Path.rename
        def rename(path, destination):
            if path == old.parent:
                raise OSError(errno.EXDEV, "overlay lower directory")
            if path.name == image.RELEASE:
                raise OSError(errno.EIO, "replacement failed")
            return original_rename(path, destination)
        with patch.object(image, "package_stream", side_effect=lambda _: self.archive({"vmlinuz": b"new"})), \
                patch.object(Path, "rename", rename):
            with self.assertRaisesRegex(OSError, "replacement failed"):
                image.replace_tree(Path("unused"), {"vmlinuz": hashlib.sha256(b"new").hexdigest()}, self.root)
        self.assertEqual(old.read_bytes(), b"old")
        self.assertEqual({path.name for path in old.parent.parent.iterdir()}, {image.RELEASE})

    def test_symlink_target_or_parent_and_other_release_fail(self):
        for name in ("/usr", "/usr/lib", "/usr/lib/modules", image.TARGET):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target = image.policy.path_at(root, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(self.root, target_is_directory=True)
                with self.assertRaises(image.VerificationError):
                    image.validate_target(root)
        self.write(image.TARGET + "/vmlinuz")
        self.write("/usr/lib/modules/other/vmlinuz")
        with self.assertRaisesRegex(image.VerificationError, "releases"):
            image.validate_target(self.root)

    def test_delta_allows_only_exact_release_not_prefix_neighbors(self):
        before = {"/etc/unchanged": {"sha256": "same"}, image.TARGET + "/vmlinuz": {"sha256": "old"}}
        after = {**before, image.TARGET + "/vmlinuz": {"sha256": "new"}, image.TARGET + "/initramfs.img": {}}
        image.verify_protected_delta(before, after)
        for path in ("/etc/unchanged", "/usr/lib/firmware/file", "/boot/file", "/usr/libexec/armada/tool",
                     "/usr/lib/modules", image.TARGET + "-extra/vmlinuz", "/usr/lib/modules/7.2.4/vmlinuz"):
            with self.subTest(path=path), self.assertRaises(image.VerificationError):
                image.verify_protected_delta(before, {**after, path: {"sha256": "changed"}})
        with self.assertRaises(image.VerificationError):
            image.verify_protected_delta({"/etc/missing": None}, {})

    def test_initramfs_listing_tracks_present_and_absent_charging_module(self):
        files = self.inventory()
        name = "usr/" + image.PREFIX + image.MODULE
        modules = image.initramfs_listing(self.listing(name), files)
        self.assertEqual(modules[name], (image.MODULE, None))
        other = "lib/modules/7.2.3/kernel/test/module0.ko.xz"
        self.assertEqual(image.initramfs_listing(self.listing(other), files)[other], ("kernel/test/module0.ko", "xz"))
        self.assertNotIn(name, image.initramfs_listing(self.listing(other), files))

    def test_initramfs_listing_rejects_missing_helper_wrong_release_links_and_duplicates(self):
        name = "usr/" + image.PREFIX + image.MODULE
        good = self.listing(name)
        bad = (good.replace(image.BOOT_HELPERS[0], image.BOOT_HELPERS[0] + "-extra"),
               good.replace("/7.2.3/", "/7.2.4/"),
               good + "\n" + good.splitlines()[-1],
               good.replace(name, name + " -> /old.ko").replace("-rw-r--r-- 1 root root 123 Jan 1 00:00 " + name,
                                                                               "lrwxrwxrwx 1 root root 123 Jan 1 00:00 " + name),
               good.replace(image.MODULE, "kernel/unknown.ko"),
               good + "\n-rw-r--r-- 1 root root 123 Jan 1 00:00 lib/" + image.PREFIX[4:] + image.MODULE)
        for listing in bad:
            with self.subTest(listing=listing), self.assertRaises(image.VerificationError):
                image.initramfs_listing(listing, self.inventory())

    def test_initramfs_embedded_module_hash_is_checked_not_just_name(self):
        self.write(image.TARGET + "/initramfs.img", b"generated")
        name = "usr/" + image.PREFIX + image.MODULE
        contents = b"new-module"
        files = {image.MODULE: hashlib.sha256(contents).hexdigest()}
        def unpack(arguments, **kwargs):
            destination = Path(kwargs["cwd"]) / name
            destination.parent.mkdir(parents=True)
            destination.write_bytes(contents)
            return subprocess.CompletedProcess(arguments, 0, "", "")
        with patch.object(image.policy, "run", return_value=subprocess.CompletedProcess([], 0, self.listing(name), "")), \
                patch.object(image.subprocess, "run", side_effect=unpack):
            result = image.verify_initramfs(files, self.root)
            self.assertTrue(result["qcom_battmgr_present"])
            self.assertEqual(result["modules_checked"], 1)
            with self.assertRaisesRegex(image.VerificationError, "Stale"):
                image.verify_initramfs({image.MODULE: "old"}, self.root)

    def test_input_manifest_rejects_symlinks_and_records_all_inputs(self):
        self.write("/inputs/kernel/patches/series", b"series")
        self.write("/inputs/ARMADA-LICENSE.md", b"license")
        self.assertEqual(len(image.input_hashes(self.root / "inputs")), 2)
        (self.root / "inputs/link").symlink_to("ARMADA-LICENSE.md")
        with self.assertRaises(image.VerificationError):
            image.input_hashes(self.root / "inputs")

    def test_loading_original_verifier_does_not_write_input_bytecode(self):
        path = self.write("/inputs/verifier.py", b"PATCH_SHA256 = 'original'\n")
        before = image.input_hashes(self.root / "inputs")
        verifier = image.load_module("fixture_verifier", path)
        verifier.PATCH_SHA256 = "reviewed"
        self.assertEqual(image.input_hashes(self.root / "inputs"), before)

    def receipt(self):
        files = {name: image.PINNED_FILES.get(name, "a" * 64) for name in self.inventory()}
        files.update({name: "b" * 64 for name in image.METADATA})
        sources = {"verify-kpfe-kernel-package.py": image.VERIFIER_SHA256,
                   "kernel/patches/" + image.PATCH: image.PATCH_SHA256}
        return {
            "schema_version": 1, "status": "PASS", "archive_sha256": image.ARCHIVE_SHA256,
            "patch_0950_sha256": image.PATCH_SHA256, "verifier_sha256": image.VERIFIER_SHA256,
            "producer_sha256": image.policy.sha256(Path(image.__file__)),
            "package_verification": image.expected_report(files), "counts": image.validate_inventory(files),
            "files_sha256": files, "kernel_build_inputs_sha256": sources,
        }

    def test_receipt_requires_success_pins_and_exact_report(self):
        good = self.receipt()
        image.validate_receipt(good, good["kernel_build_inputs_sha256"])
        for key, value in (("schema_version", True), ("status", "FAIL"), ("archive_sha256", "old"),
                           ("patch_0950_sha256", "old"), ("verifier_sha256", "old"),
                           ("producer_sha256", "old"), ("counts", {"modules": 1618, "dtbs": 25})):
            receipt = deepcopy(good)
            receipt[key] = value
            with self.subTest(key=key), self.assertRaises(image.VerificationError):
                image.validate_receipt(receipt, good["kernel_build_inputs_sha256"])
        for key, value in (("status", "FAIL"), ("scope", "hardware-verified"), ("release", "7.2.4"),
                           ("vermagic", "7.2.3 x86_64"), ("worker_symbols", []), ("modules", 1618),
                           ("vmlinuz_sha256", "old"), ("qcom_battmgr_sha256", "old"),
                           ("dtbs_sha256", {}), ("metadata_sha256", {}), ("not_validated", [])):
            receipt = deepcopy(good)
            receipt["package_verification"][key] = value
            with self.subTest(report_key=key), self.assertRaises(image.VerificationError):
                image.validate_receipt(receipt, good["kernel_build_inputs_sha256"])
        with self.assertRaises(image.VerificationError):
            image.validate_receipt([], good["kernel_build_inputs_sha256"])

    def test_receipt_rejects_changed_inputs_missing_files_or_invalid_hashes(self):
        good = self.receipt()
        with self.assertRaisesRegex(image.VerificationError, "source inputs"):
            image.validate_receipt(good, {**good["kernel_build_inputs_sha256"], "kernel/changed": "c" * 64})
        for name, value in ((image.MODULE, None), ("modules.order", None),
                            ("kernel/test/module0.ko", "invalid"), (image.MODULE, "c" * 64)):
            receipt = deepcopy(good)
            if value is None:
                receipt["files_sha256"].pop(name)
            else:
                receipt["files_sha256"][name] = value
            with self.subTest(name=name, value=value), self.assertRaises(image.VerificationError):
                image.validate_receipt(receipt, good["kernel_build_inputs_sha256"])

    def test_receipt_consumer_rechecks_archive_and_all_files_without_readelf(self):
        receipt = self.receipt()
        path = self.write("/receipt.json", json.dumps(receipt).encode())
        archive, inputs = self.root / "archive.tar.zst", self.root / "inputs"
        reader = Mock(return_value=(receipt["files_sha256"], {}))
        verifier = SimpleNamespace(read_package=reader, verify=Mock(side_effect=AssertionError("readelf forbidden")))
        with patch.object(image, "check_archive_pin") as pin, \
                patch.object(image, "input_hashes", return_value=receipt["kernel_build_inputs_sha256"]), \
                patch.object(image, "package_verifier", return_value=verifier), \
                patch.object(image, "verify_package", side_effect=AssertionError("full verification forbidden")):
            self.assertEqual(image.load_verified_package(archive, inputs, path),
                             (receipt["package_verification"], receipt["files_sha256"]))
            pin.assert_called_once_with(archive)
            reader.assert_called_once_with(archive)
            verifier.verify.assert_not_called()
            reader.return_value = ({**receipt["files_sha256"], "kernel/test/module0.ko": "c" * 64}, {})
            with self.assertRaisesRegex(image.VerificationError, "Current archive inventory"):
                image.load_verified_package(archive, inputs, path)
            pin.side_effect = image.VerificationError("stale archive")
            with self.assertRaisesRegex(image.VerificationError, "stale archive"):
                image.load_verified_package(archive, inputs, path)

    def test_missing_invalid_or_duplicate_receipt_has_no_fallback(self):
        path = self.root / "receipt.json"
        with patch.object(image, "verify_package", side_effect=AssertionError("fallback forbidden")):
            with self.assertRaisesRegex(image.VerificationError, "regular file"):
                image.load_verified_package(receipt_path=path)
            path.write_text('{"status":"PASS","status":"FAIL"}')
            with self.assertRaisesRegex(image.VerificationError, "Duplicate"):
                image.load_verified_package(receipt_path=path)
            path.write_text("not json")
            with self.assertRaises(ValueError):
                image.load_verified_package(receipt_path=path)

    def test_runner_receipt_calls_full_verification_and_cli_does_not_install(self):
        receipt = self.receipt()
        archive, inputs = self.root / "archive.tar.zst", self.root / "inputs"
        with patch.object(image, "verify_package", return_value=(receipt["package_verification"], receipt["files_sha256"])) as full, \
                patch.object(image, "input_hashes", return_value=receipt["kernel_build_inputs_sha256"]):
            self.assertEqual(image.package_receipt(archive, inputs), receipt)
            full.assert_called_once_with(archive, inputs)
        output = io.StringIO()
        with patch.object(image, "package_receipt", return_value=receipt) as verify, \
                patch.object(image, "install", side_effect=AssertionError("installation forbidden")), redirect_stdout(output):
            image.main(["--verify-package", str(archive), str(inputs)])
            verify.assert_called_once_with(archive, inputs)
        self.assertEqual(json.loads(output.getvalue()), receipt)

    def test_installed_tree_allows_only_depmod_metadata_and_new_initramfs(self):
        files = {"vmlinuz": b"kernel", image.MODULE: b"module", "modules.dep": b"dependency"}
        for name, data in files.items():
            self.write(image.TARGET + "/" + name, data)
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        original_lstat = Path.lstat
        def owned_by_root(path):
            metadata = list(original_lstat(path))
            metadata[4:6] = [0, 0]
            return os.stat_result(metadata)
        with patch.object(Path, "lstat", owned_by_root):
            self.assertEqual(image.verify_installed(hashes, self.root), hashes)
            self.write(image.TARGET + "/initramfs.img", b"regenerated")
            self.write(image.TARGET + "/modules.dep", b"new dependencies")
            self.write(image.TARGET + "/modules.dep.bin", b"new index")
            image.verify_installed(hashes, self.root, regenerated=True)
            with self.assertRaises(image.VerificationError):
                image.verify_installed(hashes, self.root)
            self.write(image.TARGET + "/" + image.MODULE, b"stale")
            with self.assertRaisesRegex(image.VerificationError, "differs from archive"):
                image.verify_installed(hashes, self.root, regenerated=True)
            self.write(image.TARGET + "/" + image.MODULE, b"module")
            self.write(image.TARGET + "/unexpected", b"extra")
            with self.assertRaisesRegex(image.VerificationError, "unreviewed"):
                image.verify_installed(hashes, self.root, regenerated=True)

    @unittest.skipUnless(shutil.which("cpio") and shutil.which("lsinitrd"), "requires cpio and lsinitrd")
    def test_real_lsinitrd_listing_and_selective_unpack_glob(self):
        payload = self.root / "payload"
        contents = b"verified-module-bytes"
        module = "usr/" + image.PREFIX + image.MODULE
        names = (*image.BOOT_HELPERS, "usr/lib/dracut/modules.txt", module)
        for name in names:
            path = payload / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents if name == module else b"fixture\n")
        archive = subprocess.run(["cpio", "--create", "--format=newc", "--quiet"],
                                 cwd=payload, input="\n".join(names).encode() + b"\n",
                                 capture_output=True, check=True).stdout
        self.write(image.TARGET + "/initramfs.img", image.gzip.compress(archive))
        result = image.verify_initramfs({image.MODULE: hashlib.sha256(contents).hexdigest()}, self.root)
        self.assertEqual(result["modules_checked"], 1)
        self.assertTrue(result["qcom_battmgr_present"])
        self.assertEqual(result["qcom_battmgr_sha256"], hashlib.sha256(contents).hexdigest())


if __name__ == "__main__":
    unittest.main()
