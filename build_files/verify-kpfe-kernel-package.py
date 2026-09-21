#!/usr/bin/env python3
"""Check the KPFE test kernel package, without extracting or deploying it."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import sys
import tarfile
import tempfile


RELEASE = "7.2.3"
PREFIX = f"lib/modules/{RELEASE}/"
PATCH = "0950-power-supply-qcom-battmgr-kpfe-charge-policy.patch"
PATCH_SHA256 = "3477fd5cb54a81bb89fedd6bb0b0354d6dca55abfc8ef0d9d587b15c84086fad"
MODULE = "kernel/drivers/power/supply/qcom_battmgr.ko"
METADATA = (".armada-source", "modules.order", "modules.builtin", "modules.dep", "modules.alias")
WORKERS = ("qcom_battmgr_kpfe_charge_worker", "qcom_battmgr_kpfe_charge_rearm_worker")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and ".." not in path.parts
            and name == path.as_posix(), f"Unsafe archive path: {name!r}")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in name),
            f"Control character in archive path: {name!r}")
    return path


def read_module(data):
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01"
            and struct.unpack_from("<HH", data, 16) == (1, 183),
            "qcom_battmgr.ko is not a little-endian AArch64 ELF64 relocatable object")
    with tempfile.TemporaryDirectory(prefix="kpfe-kernel-check-") as directory:
        module = Path(directory) / "qcom_battmgr.ko"
        module.write_bytes(data)
        result = subprocess.run(
            ["readelf", "--wide", "--symbols", "--string-dump=.modinfo", str(module)],
            capture_output=True, text=True, check=True,
        )
    defined = {fields[7] for line in result.stdout.splitlines()
               if len(fields := line.split()) == 8 and fields[3] == "FUNC"
               and fields[6].isdigit() and fields[6] != "0"}
    for worker in WORKERS:
        require(any(name == worker or name.startswith(worker + ".") for name in defined),
                f"Missing defined charging worker: {worker}")
    vermagic = re.findall(r"^\s*\[\s*[0-9a-f]+\]\s+vermagic=(.+)$", result.stdout, re.MULTILINE)
    require(len(vermagic) == 1 and vermagic[0].split()
            and vermagic[0].split()[0] == RELEASE and "aarch64" in vermagic[0].split(),
            "Charging module vermagic does not match 7.2.3")
    return vermagic[0].strip()


def read_package(archive):
    seen, files, content = set(), {}, {}
    retained = {PREFIX + name for name in (*METADATA, MODULE)}
    process = subprocess.Popen(["zstd", "-dc", "--", str(archive)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as package:
            for member in package:
                name = member.name.rstrip("/") if member.isdir() else member.name
                path = safe_name(name)
                require(name not in seen, f"Duplicate archive member: {name}")
                seen.add(name)
                require(member.isdir() or (member.isfile() and member.sparse is None),
                        f"Link or special archive member: {name}")
                require(member.uid == 0 and member.gid == 0 and not member.mode & 0o7000,
                        f"Unexpected archive ownership or special permissions: {name}")
                require(name in {"lib", "lib/modules", PREFIX[:-1]} or name.startswith(PREFIX),
                        f"Unexpected package path or kernel release: {name}")
                require(not path.name.lower().startswith(("initrd", "initramfs"))
                        and path.name != "KERNEL", f"Boot image/initramfs in package: {name}")
                if member.isdir():
                    continue
                require(name.startswith(PREFIX) and member.size > 0,
                        f"Empty file or file outside release directory: {name}")
                require(name not in retained or member.size <= 16 * 1024 * 1024,
                        f"Oversized module or metadata: {name}")
                chunks, prefix, checksum = [], b"", hashlib.sha256()
                with package.extractfile(member) as stream:
                    while chunk := stream.read(1024 * 1024):
                        checksum.update(chunk)
                        if len(prefix) < 64:
                            prefix += chunk[:64 - len(prefix)]
                        if name in retained:
                            chunks.append(chunk)
                relative = name[len(PREFIX):]
                files[relative] = checksum.hexdigest()
                if name in retained:
                    content[relative] = b"".join(chunks)
                if relative == "vmlinuz":
                    require(prefix[56:60] == b"ARM\x64", "vmlinuz lacks the arm64 Image header")
                if relative.endswith(".dtb"):
                    require(len(prefix) >= 40 and prefix[:4] == b"\xd0\x0d\xfe\xed"
                            and struct.unpack_from(">I", prefix, 4)[0] == member.size,
                            f"Invalid DTB header/size: {relative}")
        while process.stdout.read(1024 * 1024):
            pass
        require(process.wait() == 0, "zstd integrity/decompression check failed")
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            process.wait()
    return files, content


def verify(archive, source):
    checksum = Path(str(archive) + ".sha256").read_text().split()
    require(len(checksum) == 2 and re.fullmatch(r"[0-9a-fA-F]{64}", checksum[0])
            and checksum[1] in {archive.name, "*" + archive.name},
            "Invalid SHA-256 sidecar or archive filename mismatch")
    archive_hash = digest(archive)
    require(archive_hash == checksum[0].lower(), "Archive SHA-256 mismatch")
    require(digest(source / "patches" / PATCH) == PATCH_SHA256,
            "0950 charging-policy patch differs from the approved patch")
    series = [entry for line in (source / "patches/series").read_text().splitlines()
              if (entry := line.split("#", 1)[0].strip())]
    require(series.count(PATCH) == 1, "0950 charging-policy patch must appear once in patches/series")
    expected_dtbs = {path.stem + ".dtb" for path in (source / "dts").glob("*.dts")}
    require(len(expected_dtbs) == 25, "Expected exactly 25 source DTS files")

    files, content = read_package(archive)
    require([name for name in files if PurePosixPath(name).name == "vmlinuz"] == ["vmlinuz"],
            "Expected exactly one vmlinuz at the release root")
    require(all(name in content for name in (*METADATA, MODULE)),
            "Required charging module or kernel metadata is missing")
    actual_dtbs = {name for name in files if name.endswith(".dtb")}
    require(actual_dtbs == {"dtb/qcom/" + name for name in expected_dtbs},
            "Packaged DTBs do not match the 25 source DTS filenames")
    modules = {name for name in files if name.endswith(".ko")}
    require(modules and all(name.startswith("kernel/") for name in modules),
            "Unexpected module layout")
    ordered = content["modules.order"].decode().splitlines()
    require(len(ordered) == len(set(ordered)) and set(ordered) == modules,
            "modules.order differs from the packaged module inventory")
    dependencies = {}
    for line in content["modules.dep"].decode().splitlines():
        name, separator, deps = line.partition(":")
        require(separator and name not in dependencies, "Invalid or duplicate modules.dep entry")
        dependencies[name] = deps.split()
    require(set(dependencies) == modules
            and all(dep in modules for deps in dependencies.values() for dep in deps),
            "modules.dep differs from the packaged module inventory")
    metadata = content[".armada-source"].decode().splitlines()
    require(f"Source: linux-{RELEASE} (kernel.org stable)" in metadata
            and f"Patches applied: {len(series)} (from patches/series)" in metadata
            and "DTBs included: 25 boards (SM8250 + SM8550 + SM8650 + SM8750)" in metadata
            and "Repackaged for: armada" in metadata,
            "Unexpected .armada-source metadata")
    vermagic = read_module(content[MODULE])
    return {
        "status": "PASS", "scope": "package-consistency-only", "release": RELEASE,
        "archive_sha256": archive_hash, "patch_0950_sha256": PATCH_SHA256,
        "vmlinuz_sha256": files["vmlinuz"], "qcom_battmgr_sha256": files[MODULE],
        "vermagic": vermagic, "worker_symbols": list(WORKERS), "modules": len(modules),
        "dtbs_sha256": {name: files["dtb/qcom/" + name] for name in sorted(expected_dtbs)},
        "metadata_sha256": {name: files[name] for name in METADATA},
        "not_validated": ["deployment", "bootability", "firmware RPC semantics", "hardware behavior"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="armada-kernel-7.2.3.tar.zst (with .sha256 sidecar)")
    parser.add_argument("package_source_dir", type=Path, help="packages/kernel from the build checkout")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.archive, args.package_source_dir), indent=2))
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
