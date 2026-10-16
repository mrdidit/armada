#!/usr/bin/env python3
"""Synthetic, offline checks for OCI module identity; no runtime code executes."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("iris_oci", HERE / "hash-iris-oci-module.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
REVISION = "e" * 40
MODULE = MOD.MODULE
DIRECTORY = MODULE.rsplit("/", 1)[0]


def tar(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as output:
        for name, value in entries:
            item = tarfile.TarInfo(name)
            if isinstance(value, tuple):
                item.type, item.linkname = value
                output.addfile(item)
            else:
                item.size = len(value)
                output.addfile(item, io.BytesIO(value))
    return data.getvalue()


def make_archive(path, layers, *, compressed=False, corrupt=False):
    blobs = {}
    def blob(data, media):
        digest = hashlib.sha256(data).hexdigest()
        blobs["blobs/sha256/" + digest] = data
        return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media}
    descriptors, diffids = [], []
    for entries in layers:
        data = tar(entries)
        diffids.append("sha256:" + hashlib.sha256(data).hexdigest())
        descriptors.append(blob(gzip.compress(data) if compressed else data,
                                MOD.OCI + "layer.v1.tar" + ("+gzip" if compressed else "")))
    config = {"architecture": "arm64", "os": "linux",
              "config": {"Labels": {"org.opencontainers.image.revision": REVISION,
                                    "org.opencontainers.image.version": "20261016.eeeeeee"}},
              "rootfs": {"type": "layers", "diff_ids": diffids}}
    manifest = {"schemaVersion": 2, "layers": descriptors,
                "config": blob(json.dumps(config).encode(), MOD.OCI + "config.v1+json")}
    selected = blob(json.dumps(manifest).encode(), MOD.OCI + "manifest.v1+json")
    index = {"schemaVersion": 2, "manifests": [selected]}
    if corrupt:
        first = "blobs/sha256/" + descriptors[0]["digest"][7:]
        blobs[first] = b"x" + blobs[first][1:]
    path.write_bytes(tar([("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
                          ("index.json", json.dumps(index).encode()), *blobs.items()]))
    return selected["digest"]


class ModuleHashTests(unittest.TestCase):
    def check_layers(self, layers, *, compressed=False, corrupt=False, error=None):
        with tempfile.TemporaryDirectory(dir=HERE, prefix="oci-hash-test-") as directory:
            archive = Path(directory) / "image.tar"
            digest = make_archive(archive, layers, compressed=compressed, corrupt=corrupt)
            if error:
                with self.assertRaisesRegex(ValueError, error):
                    MOD.inspect(archive, digest, REVISION)
                return None
            return MOD.inspect(archive, digest, REVISION)

    def test_original(self):
        report = self.check_layers([[(MODULE, b"module")]])
        self.assertEqual(report["module"]["sha256"], hashlib.sha256(b"module").hexdigest())
        self.assertFalse(report["device_observation_used"])

    def test_upper_layer_replaces(self):
        report = self.check_layers([[(MODULE, b"old")], [(MODULE, b"new")]])
        self.assertEqual(report["module"]["sha256"], hashlib.sha256(b"new").hexdigest())

    def test_gzip_layers_hash_stored_compressed_module_bytes(self):
        stored = gzip.compress(b"sample installed module contents")
        report = self.check_layers([[(MODULE + ".xz", stored)]], compressed=True)
        self.assertEqual(report["module"]["sha256"], hashlib.sha256(stored).hexdigest())

    def test_whiteout_deletes(self):
        self.check_layers([[(MODULE, b"old")], [(DIRECTORY + "/.wh.qcom-iris.ko", b"")]],
                          error="found 0")

    def test_whiteout_does_not_delete_same_layer_addition(self):
        report = self.check_layers([[(MODULE, b"old")],
                                   [(MODULE, b"new"), (DIRECTORY + "/.wh.qcom-iris.ko", b"")]])
        self.assertEqual(report["module"]["sha256"], hashlib.sha256(b"new").hexdigest())

    def test_opaque_whiteout_hides_older_variants_only(self):
        report = self.check_layers([[(MODULE, b"old")],
                                   [(MODULE + ".zst", b"new"), (DIRECTORY + "/.wh..wh..opq", b"")]])
        self.assertEqual(report["module"]["path"], "/" + MODULE + ".zst")

    def test_ancestor_whiteout(self):
        report = self.check_layers([[(MODULE, b"old")],
                                   [("usr/lib/.wh.modules", b""), (MODULE + ".xz", b"new")]])
        self.assertEqual(report["module"]["path"], "/" + MODULE + ".xz")

    def test_multiple_variants_rejected(self):
        self.check_layers([[(MODULE, b"one"), (MODULE + ".xz", b"two")]], error="found 2")

    def test_symlink_parent_rejected(self):
        self.check_layers([[("usr/lib/modules", (tarfile.SYMTYPE, "/elsewhere")),
                            (MODULE, b"one")]], error="Non-directory module ancestor")

    def test_hardlinked_module_rejected(self):
        self.check_layers([[(MODULE, (tarfile.LNKTYPE, "other/module"))]], error="linked")

    def test_alias_to_module_rejected(self):
        self.check_layers([[(MODULE, b"one"), ("somewhere", (tarfile.LNKTYPE, MODULE))]],
                          error="Hardlink aliases")

    def test_duplicate_layer_path_rejected(self):
        self.check_layers([[(MODULE, b"one"), (MODULE, b"two")]], error="Duplicate layer")

    def test_parent_traversal_rejected(self):
        self.check_layers([[(MODULE, b"one"), ("tmp/../x", b"unrelated")]], error="traversal")

    def test_blob_corruption_rejected(self):
        self.check_layers([[(MODULE, b"one")]], corrupt=True, error="Blob digest mismatch")

    def test_nested_module_filename_rejected(self):
        self.check_layers([[(MODULE, b"one"), (MODULE + "/child", b"impossible")]],
                          error="nested under")

    def test_unsupported_compression_rejected(self):
        descriptor = {"mediaType": MOD.OCI + "layer.v1.tar+zstd"}
        class Verified:
            def verify_blob(self, unused):
                return "unused"
        with self.assertRaisesRegex(ValueError, "Unsupported layer media type"):
            MOD.inspect_layer(Verified(), descriptor, "", {}, {})

    def test_standard_lib_alias_without_writes_is_allowed(self):
        report = self.check_layers([[("lib", (tarfile.SYMTYPE, "usr/lib")), (MODULE, b"original")]])
        self.assertEqual(report["module"]["sha256"], hashlib.sha256(b"original").hexdigest())

    def test_lib_alias_cannot_hide_later_module_replacement(self):
        self.check_layers([[("lib", (tarfile.SYMTYPE, "usr/lib")), (MODULE, b"original")],
                           [(MODULE.removeprefix("usr/"), b"replacement")]],
                          error="Noncanonical module path")

    def test_lib_alias_whiteout_rejected(self):
        self.check_layers([[("lib", (tarfile.SYMTYPE, "usr/lib")), (MODULE, b"original")],
                           [("lib/.wh.modules", b"")]], error="Noncanonical module path")

    def test_lib_alias_opaque_whiteout_rejected(self):
        self.check_layers([[("lib", (tarfile.SYMTYPE, "usr/lib")), (MODULE, b"original")],
                           [("lib/.wh..wh..opq", b"")]], error="Opaque whiteout through")

    def test_indirect_alias_into_module_tree_rejected(self):
        self.check_layers([[(MODULE, b"original"), ("lib", (tarfile.SYMTYPE, "usr/lib")),
                            ("alias", (tarfile.SYMTYPE, "lib"))],
                           [("alias/modules/7.2.6/kernel/drivers/media/platform/qcom/iris/qcom-iris.ko",
                             b"replacement")]], error="Alias can reach")

    def test_generic_alias_into_module_directory_rejected(self):
        self.check_layers([[(MODULE, b"original"), ("alias", (tarfile.SYMTYPE, DIRECTORY))],
                           [("alias/qcom-iris.ko", b"replacement")]], error="Alias can reach")

    def test_alias_target_parent_resolution_after_symlink(self):
        # Lexical normalization would resolve alias to /iris, overlooking that
        # the intermediate symlink changes the meaning of '..'.
        self.check_layers([[(MODULE, b"original"),
                            ("intermediate", (tarfile.SYMTYPE, DIRECTORY + "/other")),
                            ("alias", (tarfile.SYMTYPE, "intermediate/../qcom-iris.ko"))]],
                          error="Alias can reach")


if __name__ == "__main__":
    unittest.main(verbosity=2)
