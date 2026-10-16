#!/usr/bin/env python3
"""Hash installed Iris and Gamescope in a pinned, local OCI archive without unpacking.

Only regular-file artifact paths and directory parents are supported. Relevant
links, sparse files, unknown compression, and malformed changesets fail closed.
No image commands execute and no network access occurs.
"""

import argparse
import contextlib
from collections import deque
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile


OCI = "application/vnd.oci.image."
MODULE = "usr/lib/modules/7.2.6/kernel/drivers/media/platform/qcom/iris/qcom-iris.ko"
TARGETS = {MODULE, MODULE + ".xz", MODULE + ".zst"}
GAMESCOPE = "usr/bin/gamescope"
BUILD_IDS = "usr/lib/.build-id"
ARTIFACTS = TARGETS | {GAMESCOPE}
GAMESCOPE_ALIASES = ("bin", "sbin", "usr/sbin")
STANDARD_ALIASES = {
    "lib": ({"usr/lib", "/usr/lib"}, "usr/lib"),
    "bin": ({"usr/bin", "/usr/bin"}, "usr/bin"),
    "sbin": ({"usr/sbin", "/usr/sbin", "usr/bin", "/usr/bin"}, "usr/bin"),
    "usr/sbin": ({"bin", "/usr/bin"}, "usr/bin"),
}
PARENTS = set()
for _name in ARTIFACTS:
    _parts = _name.split("/")
    PARENTS.update("/".join(_parts[:i]) for i in range(1, len(_parts)))
MAX_JSON = 4 * 1024**2
MAX_MODULE = 16 * 1024**2
MAX_GAMESCOPE = 128 * 1024**2
MAX_LAYER = 64 * 1024**3


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(name):
    require(isinstance(name, str) and "\x00" not in name, "Invalid archive path")
    require(not name.startswith("/"), f"Absolute archive path: {name!r}")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    require(".." not in parts, f"Parent traversal: {name!r}")
    return "/".join(parts)


def descendant(path, ancestor):
    return not ancestor or path == ancestor or path.startswith(ancestor + "/")


def protected(path):
    return path in PARENTS or not path or any(descendant(path, target) for target in ARTIFACTS)


def check_alias_write(path):
    # Permit standard merged-/usr links themselves, never artifact changesets
    # written through them as if they were a distinct safe filesystem.
    require(not descendant(path, "lib/modules"),
            f"Noncanonical module path through /lib: {path}")
    require(not descendant(path, "lib/.build-id"),
            f"Noncanonical build-ID path through /lib: {path}")
    require(not any(descendant(path, alias + "/gamescope") for alias in GAMESCOPE_ALIASES),
            f"Noncanonical Gamescope path through a merged-/usr alias: {path}")


def resolve_aliases(parts, links):
    """Resolve every historical link possibility; ambiguity is conservative.

    Links are retained even after deletion/replacement. This may reject a valid
    image, but prevents accepting a hash by overlooking an alias from a layer.
    '..' is interpreted after preceding symlinks, not normalized beforehand.
    """
    pending = [((), tuple(parts), 0)]
    resolved, visited = set(), set()
    while pending:
        base, tail, hops = pending.pop()
        require(hops <= 64 and len(visited) <= 10000, "Alias resolution is cyclic or excessive")
        key = (base, tail)
        require(key not in visited, "Cyclic or ambiguous historical alias resolution")
        visited.add(key)
        queue = deque(tail)
        while queue:
            part = queue.popleft()
            if part in ("", "."):
                continue
            if part == "..":
                base = base[:-1]
                continue
            candidate = "/".join((*base, part))
            if candidate in links:
                for target, hardlink in links[candidate]:
                    root = () if target.startswith("/") or hardlink else base
                    pending.append((root, tuple(target.split("/")) + tuple(queue), hops + 1))
                break
            base = (*base, part)
        else:
            resolved.add("/".join(base))
    return resolved


def verify_aliases(links, changes):
    build_ids = {path for path, variants in links.items()
                 if re.fullmatch(r"usr/lib/\.build-id/[0-9a-f]{2}/[0-9a-f]{38}", path)
                 and ("../../../../usr/bin/gamescope", False) in variants}
    build_id_parents = set()
    for path in build_ids:
        parts = path.split("/")
        build_id_parents.update("/".join(parts[:i]) for i in range(1, len(parts)))
    for path, variants in links.items():
        for target, hardlink in variants:
            # Start at a symlink's containing directory; hardlinks use root.
            prefix = [] if target.startswith("/") or hardlink else path.split("/")[:-1]
            destinations = resolve_aliases(prefix + target.split("/"), links)
            targets, destination = STANDARD_ALIASES.get(path, (set(), None))
            standard_alias = (not hardlink and target in targets and
                              destinations == {destination})
            build_id = (not hardlink and
                        re.fullmatch(r"usr/lib/\.build-id/[0-9a-f]{2}/[0-9a-f]{38}", path) and
                        target == "../../../../usr/bin/gamescope" and
                        destinations == {GAMESCOPE} and len(variants) == 1)
            if build_id:
                require(not any(other != path and
                                (descendant(path, other) or descendant(other, path))
                                for other in links), "Linked build-ID ancestor or descendant")
                require(not any(descendant(changed, path) or
                                (not directory and descendant(path, changed))
                                for changed, directory in changes),
                        "Build-ID alias modified by another changeset")
            require(standard_alias or build_id or not any(
                    protected(p) or p in build_id_parents or
                    any(descendant(p, build_id_path) for build_id_path in build_ids)
                    for p in destinations),
                    f"Alias can reach an artifact or its ancestors: {path} -> {target}")


class HashReader:
    def __init__(self, source, limit):
        self.source, self.limit = source, limit
        self.digest, self.size = hashlib.sha256(), 0

    def read(self, amount=-1):
        require(amount >= 0, "Unbounded read rejected")
        data = self.source.read(amount)
        self.size += len(data)
        require(self.size <= self.limit, "Expanded layer exceeds size limit")
        self.digest.update(data)
        return data


class Archive:
    def __init__(self, path):
        # OCI archives are uncompressed outer tar files containing compressed blobs.
        self.tar = tarfile.open(path, "r:")
        self.members = {}
        for member in self.tar:
            name = canonical(member.name)
            require(name not in self.members, f"Duplicate archive member: {name}")
            require(member.isdir() or member.isreg(), f"Linked/special archive member: {name}")
            require(not member.sparse, "Sparse archive member rejected")
            self.members[name] = member
            require(len(self.members) <= 4096, "Excessive OCI archive member count")

    def open_member(self, name):
        require(name in self.members, f"Missing archive member: {name}")
        member = self.members[name]
        require(member.isreg(), f"Not a regular archive member: {name}")
        return self.tar.extractfile(member)

    def small_json(self, name):
        require(self.members[name].size <= MAX_JSON, f"JSON too large: {name}")
        with self.open_member(name) as source:
            return json.load(source)

    def verify_blob(self, descriptor):
        digest = descriptor.get("digest", "")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "Unsupported blob digest")
        require(not descriptor.get("urls"), "External blob URL rejected")
        name = "blobs/sha256/" + digest[7:]
        require(name in self.members, f"Blob absent: {digest}")
        require(type(descriptor.get("size")) is int and
                self.members[name].size == descriptor["size"], "Blob size mismatch")
        with self.open_member(name) as source:
            actual = hashlib.file_digest(source, "sha256").hexdigest()
        require(actual == digest[7:], f"Blob digest mismatch: {digest}")
        return name


def inspect_layer(archive, descriptor, expected_diffid, state, links, changes):
    name = archive.verify_blob(descriptor)
    media = descriptor.get("mediaType")
    require(media in (OCI + "layer.v1.tar", OCI + "layer.v1.tar+gzip"),
            f"Unsupported layer media type (no hash produced): {media}")
    added, removed, seen = {}, [], set()
    with contextlib.ExitStack() as stack:
        source = stack.enter_context(archive.open_member(name))
        if media.endswith("+gzip"):
            source = stack.enter_context(gzip.GzipFile(fileobj=source))
        hashed = HashReader(source, MAX_LAYER)
        layer = stack.enter_context(tarfile.open(fileobj=hashed, mode="r|"))
        for member in layer:
            path = canonical(member.name)
            require(path not in seen, f"Duplicate layer member: {path}")
            seen.add(path)
            require(len(seen) <= 2_000_000, "Excessive layer member count")
            require(not any("overlay." in key for key in member.pax_headers),
                    "Overlay xattr whiteouts unsupported")
            parent, _, base = path.rpartition("/")
            check_alias_write(path)
            if descendant(path, BUILD_IDS) and not member.issym():
                changes.add((path, member.isdir()))
            if base.startswith(".wh."):
                require(member.isreg() and member.size == 0,
                        f"Malformed OCI whiteout: {path}")
                if base == ".wh..wh..opq":
                    require(parent not in ("lib", *GAMESCOPE_ALIASES),
                            f"Opaque whiteout through /{parent} alias")
                    removed.append(parent)
                else:
                    require(base[4:] not in ("", ".", "..") and
                            not base[4:].startswith(".wh."),
                            f"Unsupported reserved whiteout: {path}")
                    removed_path = (parent + "/" if parent else "") + base[4:]
                    check_alias_write(removed_path)
                    removed.append(removed_path)
                if descendant(removed[-1], BUILD_IDS) or descendant(BUILD_IDS, removed[-1]):
                    changes.add((removed[-1], False))
                continue
            if member.issym() or member.islnk():
                require("\x00" not in member.linkname and member.linkname,
                        f"Invalid link target: {path}")
                links.setdefault(path, set()).add((member.linkname, member.islnk()))
            if path in PARENTS:
                require(member.isdir(), f"Non-directory artifact ancestor: {path}")
            require(not any(path != target and descendant(path, target) for target in ARTIFACTS),
                    f"Entry nested under an artifact filename: {path}")
            if member.islnk():
                linked = canonical(member.linkname)
                require(linked not in ARTIFACTS and linked not in PARENTS,
                        f"Hardlink aliases an artifact or its ancestors: {path}")
            if path not in ARTIFACTS:
                continue
            artifact = "Gamescope" if path == GAMESCOPE else "Module"
            require(member.isreg() and not member.sparse,
                    f"{artifact} is linked, sparse or nonregular: {path}")
            limit = MAX_GAMESCOPE if path == GAMESCOPE else MAX_MODULE
            require(0 < member.size <= limit, f"Invalid {artifact.lower()} size")
            with layer.extractfile(member) as source_file:
                digest = hashlib.file_digest(source_file, "sha256").hexdigest()
            added[path] = {"path": "/" + path, "sha256": digest,
                           "size": member.size, "layer_digest": descriptor["digest"]}
        # Complete decompression also validates gzip CRC and the full OCI diff ID.
        while hashed.read(1024**2):
            pass
        require("sha256:" + hashed.digest.hexdigest() == expected_diffid,
                "Uncompressed layer digest mismatch")
    # Whiteouts hide lower layers only, regardless of their position in this tar.
    for path in list(state):
        if any(descendant(path, removed_path) for removed_path in removed):
            del state[path]
    state.update(added)
    return {"digest": descriptor["digest"], "diff_id": expected_diffid,
            "members": len(seen), "expanded_bytes": hashed.size,
            "module_changes": [path for path in added if path in TARGETS],
            "gamescope_changes": [path for path in added if path == GAMESCOPE],
            "whiteouts": len(removed)}


def inspect(path, expected_manifest, expected_revision):
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", expected_manifest), "Invalid manifest digest")
    require(re.fullmatch(r"[0-9a-f]{40}", expected_revision), "Invalid source revision")
    archive = Archive(path)
    try:
        require(archive.small_json("oci-layout") == {"imageLayoutVersion": "1.0.0"},
                "Unsupported OCI layout")
        index = archive.small_json("index.json")
        require(index.get("schemaVersion") == 2, "Invalid index schema")
        descriptors = index.get("manifests", [])
        require(len(descriptors) == 1 and descriptors[0].get("digest") == expected_manifest,
                "Archive index does not select exactly the pinned image")
        require(descriptors[0].get("mediaType") == OCI + "manifest.v1+json",
                "Nested index or unsupported manifest rejected")
        manifest = archive.small_json(archive.verify_blob(descriptors[0]))
        require(manifest.get("schemaVersion") == 2, "Invalid image manifest")
        require(manifest["config"].get("mediaType") == OCI + "config.v1+json",
                "Unsupported image config")
        config = archive.small_json(archive.verify_blob(manifest["config"]))
        require(config.get("architecture") == "arm64" and config.get("os") == "linux",
                "Image is not Linux ARM64")
        labels = config.get("config", {}).get("Labels", {})
        require(labels.get("org.opencontainers.image.revision") == expected_revision,
                "Source revision mismatch")
        layers = manifest.get("layers", [])
        diffids = config.get("rootfs", {}).get("diff_ids", [])
        require(config.get("rootfs", {}).get("type") == "layers" and
                1 <= len(layers) <= 128 and len(layers) == len(diffids), "Invalid layer list")
        state, evidence, links, changes = {}, [], {}, set()
        for layer, diffid in zip(layers, diffids):
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", diffid), "Invalid diff ID")
            evidence.append(inspect_layer(archive, layer, diffid, state, links, changes))
        verify_aliases(links, changes)
        modules = [value for path, value in state.items() if path in TARGETS]
        require(len(modules) == 1, f"Expected exactly one installed module, found {len(modules)}")
        require(GAMESCOPE in state, "Missing installed Gamescope at /usr/bin/gamescope")
        return {"manifest_digest": expected_manifest, "image_revision": expected_revision,
                "image_version": labels.get("org.opencontainers.image.version"),
                "module": modules[0], "gamescope": state[GAMESCOPE], "layers_verified": evidence,
                "method": "OCI layer content hashes with relevant whiteout application; no image execution",
                "device_observation_used": False}
    finally:
        archive.tar.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--manifest-digest", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.archive, args.manifest_digest, args.revision)
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps(result["module"], sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, tarfile.TarError) as exc:
        print(f"No module hash accepted: {exc}", file=sys.stderr)
        sys.exit(1)
