# SPDX-License-Identifier: GPL-2.0-or-later
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "scoped_inputs", Path(__file__).resolve().parents[1] / "build_files/prepare-scoped-image-inputs.py")
inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inputs)


def archive_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
            member.size = len(content) if kind == tarfile.REGTYPE else 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = "../escape"
            archive.addfile(member, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


class ScopedInputTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "source"
        (self.source / "patches").mkdir(parents=True)
        (self.source / "BASE.env").write_bytes(b"VERSION=7.2.3\n")
        (self.source / "patches/0950.patch").write_bytes(b"corrected patch\n")
        self.nested = [
            ("./", b"", tarfile.DIRTYPE),
            ("./kernel/", b"", tarfile.DIRTYPE),
            ("./kernel/patches/", b"", tarfile.DIRTYPE),
            ("./kernel/BASE.env", b"VERSION=7.2.3\n", tarfile.REGTYPE),
            ("./kernel/patches/0950.patch", b"corrected patch\n", tarfile.REGTYPE),
            *(("./" + name, b"retained source metadata", tarfile.REGTYPE)
              for name in sorted(inputs.SOURCE_METADATA)),
        ]
        self.manifest = self.root / "manifest.sha256"
        self.bundle = self.root / "inputs.tar.gz"
        self.policy = self.root / "policy"
        self.kernel = self.root / "kernel"

    def bundle_entries(self):
        files = {f"rpms/package-{index}.rpm": b"runtime" for index in range(4)}
        files.update({f"srpms/package-{index}.src.rpm": b"source" for index in range(3)})
        files.update({"kernel/kernel.tar.zst": b"kernel",
                      "kernel/kernel.tar.zst.sha256": b"checksum",
                      "kernel-sources/linux.tar.xz": b"upstream source",
                      inputs.SOURCE_ARCHIVE: archive_bytes(self.nested)})
        manifest = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                           for name, data in sorted(files.items())).encode()
        self.manifest.write_bytes(manifest)
        files["SHA256SUMS"] = manifest
        return [(name, content, tarfile.REGTYPE) for name, content in files.items()]

    def prepare(self, entries=None):
        if entries is None:
            entries = self.bundle_entries()
        self.bundle.write_bytes(archive_bytes(entries))
        inputs.prepare(self.bundle, self.policy, self.kernel,
                       manifest=self.manifest, kernel_source=self.source)

    def test_extracts_pinned_inputs_and_matching_public_sources(self):
        entries = self.bundle_entries()
        entries.insert(0, ("rpms/", b"", tarfile.DIRTYPE))
        self.prepare(entries)
        self.assertEqual((self.policy / "SHA256SUMS").read_bytes(), self.manifest.read_bytes())
        self.assertEqual(inputs.tree_inventory(self.kernel / "kernel"),
                         inputs.tree_inventory(self.source))
        self.assertTrue((self.kernel / "verify-kpfe-kernel-package.py").is_file())

    def test_wrong_hash_is_rejected_before_extraction(self):
        entries = self.bundle_entries()
        entries[0] = (entries[0][0], b"changed", tarfile.REGTYPE)
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.prepare(entries)
        self.assertFalse(self.policy.exists())

    def test_embedded_manifest_must_equal_tracked_manifest(self):
        entries = self.bundle_entries()
        entries[-1] = ("SHA256SUMS", b"untrusted manifest", tarfile.REGTYPE)
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch: SHA256SUMS"):
            self.prepare(entries)

    def test_outer_inventory_missing_or_unexpected_is_rejected(self):
        for extra in (None, ("private-notes.md", b"private", tarfile.REGTYPE),
                      ("unexpected/", b"", tarfile.DIRTYPE)):
            with self.subTest(extra=extra):
                entries = self.bundle_entries()
                entries = entries[1:] if extra is None else entries + [extra]
                with self.assertRaisesRegex(ValueError, "Missing archive|Unexpected archive"):
                    self.prepare(entries)
                self.assertFalse(self.policy.exists())

    def test_duplicate_canonical_paths_are_rejected(self):
        entries = self.bundle_entries()
        name, data, kind = entries[0]
        entries.append(("./" + name, data, kind))
        with self.assertRaisesRegex(ValueError, "Duplicate archive"):
            self.prepare(entries)

    def test_unsafe_paths_are_rejected(self):
        for name in ("/escape", "../escape", "rpms/../escape", "rpms//escape",
                     "rpms/./escape", "rpms\\escape", "rpms/line\nbreak"):
            with self.subTest(name=name):
                entries = self.bundle_entries() + [(name, b"unsafe", tarfile.REGTYPE)]
                with self.assertRaisesRegex(ValueError, "Unsafe archive path"):
                    self.prepare(entries)

    def test_outer_links_and_special_files_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                entries = self.bundle_entries()
                entries[0] = (entries[0][0], b"", kind)
                with self.assertRaisesRegex(ValueError, "Link or special archive"):
                    self.prepare(entries)

    def test_unexpected_nested_path_is_rejected(self):
        self.nested.append(("./private-notes.md", b"private", tarfile.REGTYPE))
        with self.assertRaisesRegex(ValueError, "Unexpected archive file"):
            self.prepare()
        self.assertFalse(self.kernel.exists())

    def test_nested_link_is_rejected(self):
        self.nested[3] = ("./kernel/BASE.env", b"", tarfile.SYMTYPE)
        with self.assertRaisesRegex(ValueError, "Link or special archive"):
            self.prepare()

    def test_incomplete_nested_kernel_is_rejected(self):
        del self.nested[3]
        with self.assertRaisesRegex(ValueError, "Missing archive files"):
            self.prepare()

    def test_kernel_byte_difference_is_rejected(self):
        self.nested[3] = ("./kernel/BASE.env", b"VERSION=other\n", tarfile.REGTYPE)
        with self.assertRaisesRegex(ValueError, "differ from the public checkout"):
            self.prepare()

    def test_existing_output_is_never_overwritten(self):
        self.policy.mkdir()
        marker = self.policy / "preserved"
        marker.write_text("original")
        with self.assertRaisesRegex(ValueError, "Output already exists"):
            self.prepare()
        self.assertEqual(marker.read_text(), "original")

    def test_symlink_in_public_source_is_rejected(self):
        (self.source / "link").symlink_to(self.source / "BASE.env")
        with self.assertRaisesRegex(ValueError, "Link or special kernel source"):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
