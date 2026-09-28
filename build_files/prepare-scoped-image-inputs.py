#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Extract only the pinned image inputs and matching public kernel sources."""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "build_files/scoped-image-inputs.sha256"
KERNEL_SOURCE = ROOT / "packages/kernel"
SOURCE_ARCHIVE = "kernel-sources/armada-kernel-inputs.tar.gz"
SOURCE_METADATA = {"verify-kpfe-kernel-package.py", "ARMADA-LICENSE.md", "PROVENANCE.json"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_name(name, *, directory=False):
    require(name and not any(ord(char) < 32 or ord(char) == 127 for char in name)
            and "\\" not in name, f"Unsafe archive path: {name!r}")
    if directory and name.endswith("/"):
        name = name[:-1]
    if name.startswith("./"):
        name = name[2:]
    if name == "." and directory:
        return name
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and ".." not in path.parts
            and name != "." and name == path.as_posix(), f"Unsafe archive path: {name!r}")
    return name


def read_manifest(path):
    data = path.read_bytes()
    entries = {}
    for line in data.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, "Malformed pinned input manifest")
        name = safe_name(match[2])
        require(name == match[2] and name not in entries and name != "SHA256SUMS",
                "Duplicate or noncanonical pinned input path")
        entries[name] = match[1]
    require(len(entries) == 11 and SOURCE_ARCHIVE in entries,
            "Expected exactly eleven pinned input files")
    return data, entries


def parents(names):
    return {str(parent) for name in names for parent in PurePosixPath(name).parents}


def archive_members(archive, expected_files, expected_dirs, hashes=None):
    seen, files, members = set(), set(), []
    for member in archive.getmembers():
        name = safe_name(member.name, directory=member.isdir())
        require(name not in seen, f"Duplicate archive member: {name}")
        seen.add(name)
        require(member.isdir() or (member.isfile() and member.sparse is None),
                f"Link or special archive member: {name}")
        require(not member.mode & 0o7000, f"Special archive permissions: {name}")
        if member.isdir():
            require(name in expected_dirs, f"Unexpected archive directory: {name}")
        else:
            require(name in expected_files, f"Unexpected archive file: {name}")
            files.add(name)
            if hashes and name in hashes:
                with archive.extractfile(member) as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                require(digest == hashes[name], f"SHA-256 mismatch: {name}")
        members.append(member.replace(name=name))
    require(files == set(expected_files),
            f"Missing archive files: {sorted(set(expected_files) - files)}")
    return members


def tree_inventory(root):
    require(root.is_dir() and not root.is_symlink(), f"Invalid kernel source directory: {root}")
    files, directories = {}, set()
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            directories.add(name)
        else:
            require(stat.S_ISREG(mode), f"Link or special kernel source: {name}")
            with path.open("rb") as stream:
                files[name] = hashlib.file_digest(stream, "sha256").hexdigest()
    require(files, "Empty kernel source tree")
    return files, directories


def prepare(input_tar, policy_output, kernel_output, *, manifest=MANIFEST, kernel_source=KERNEL_SOURCE):
    for output in (policy_output, kernel_output):
        require(not os.path.lexists(output), f"Output already exists: {output}")
        require(output.parent.is_dir(), f"Output parent is missing: {output.parent}")
    policy_output, kernel_output = policy_output.resolve(), kernel_output.resolve()
    require(not policy_output.is_relative_to(kernel_output)
            and not kernel_output.is_relative_to(policy_output), "Output directories overlap")
    manifest_data, hashes = read_manifest(manifest)
    hashes["SHA256SUMS"] = hashlib.sha256(manifest_data).hexdigest()
    kernel_files, kernel_dirs = tree_inventory(kernel_source)
    with tarfile.open(input_tar, "r:gz") as archive:
        members = archive_members(archive, hashes, parents(hashes), hashes)
        policy_output.mkdir()
        archive.extractall(policy_output, members=members, filter="data")

    expected_files = {"kernel/" + name for name in kernel_files} | SOURCE_METADATA
    expected_dirs = {".", "kernel"} | {"kernel/" + name for name in kernel_dirs}
    with tarfile.open(policy_output / SOURCE_ARCHIVE, "r:gz") as archive:
        members = archive_members(archive, expected_files, expected_dirs)
        kernel_output.mkdir()
        archive.extractall(kernel_output, members=members, filter="data")
    require(tree_inventory(kernel_output / "kernel") == (kernel_files, kernel_dirs),
            "Extracted kernel sources differ from the public checkout")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_tar", type=Path)
    parser.add_argument("policy_output", type=Path)
    parser.add_argument("kernel_source_output", type=Path)
    args = parser.parse_args()
    try:
        prepare(args.input_tar, args.policy_output, args.kernel_source_output)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f"Input verification failed: {error}\n")
    print("Verified eleven image inputs and exact public kernel source inventory.")


if __name__ == "__main__":
    main()
