#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Replace only the reviewed kernel tree in an offline ARM64 image build."""

from contextlib import contextmanager
import argparse
import errno
import gzip
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


POLICY_PATH = Path(__file__).with_name("install-charging-policy.py")
policy = load_module("charging_policy_image", POLICY_PATH)
require = policy.require
VerificationError = policy.VerificationError
RELEASE = "7.2.3"
TARGET = f"/usr/lib/modules/{RELEASE}"
PREFIX = f"lib/modules/{RELEASE}/"
ARCHIVE = Path(f"/packages/kernel/armada-kernel-{RELEASE}.tar.zst")
ARCHIVE_SHA256 = "0814bed69d64a188db231e3c927156ad40d5d02a1db98e7cd900cc5943c48148"
INPUTS = Path("/ctx/kernel-inputs")
VERIFICATION_PATH = Path("/ctx/kernel-verification.json")
PATCH_SHA256 = "d6e3fd90a18270675bf03e96880d8be6ba72e2981742bbad3bd433dcbe35fa36"
VERIFIER_SHA256 = "f17fb4680db8b74490077b565013cc21bff6ca7f8afc0c861e4effe742b1f16c"
HELPER = Path("/ctx/build_files/55-generate-initramfs.sh")
HELPER_SHA256 = "00130f359e7fb307a014e90246b6ce5d26b20770e154c0e024239ae3ee6836b0"
EVIDENCE_PATH = Path("/usr/share/armada-charging/kernel-image-verification.json")
MODULE = "kernel/drivers/power/supply/qcom_battmgr.ko"
PATCH = "0950-power-supply-qcom-battmgr-kpfe-charge-policy.patch"
METADATA = (".armada-source", "modules.order", "modules.builtin", "modules.dep", "modules.alias")
WORKERS = ("qcom_battmgr_kpfe_charge_worker", "qcom_battmgr_kpfe_charge_rearm_worker")
VERMAGIC = "7.2.3 SMP preempt mod_unload aarch64"
NOT_VALIDATED = ["deployment", "bootability", "firmware RPC semantics", "hardware behavior"]
PINNED_FILES = {
    "vmlinuz": "8f08d255b351fa61468914bb555a83e07d584a1128e9b5df946453056d7fa073",
    MODULE: "24c67ead5ffe3c5f7b2fbd38bb51acecc405b5f99e187187462ba3451eb9f813",
    "dtb/qcom/sm8750-konkr-pf-elite.dtb": "36f7c276ebd156c0dbfe86dd6092ea9d6b365759698383088554a86178fc72b7",
}
DEPMOD_FILES = {
    "modules.dep", "modules.dep.bin", "modules.alias", "modules.alias.bin",
    "modules.symbols", "modules.symbols.bin", "modules.softdep", "modules.weakdep",
    "modules.devname", "modules.builtin.bin", "modules.builtin.alias.bin",
}
BOOT_HELPERS = (
    "usr/lib/systemd/system/armada-splash-initrd.service",
    "usr/lib/systemd/system/dracut-pre-mount.service.d/armada-splash.conf",
    "usr/libexec/armada/armada-splash",
    "usr/libexec/armada/armada-splash-launcher",
    "usr/libexec/armada/device-env",
    "usr/share/armada/splash/splash.asp",
    "usr/libexec/armada/armada-ostree-fallback",
    "usr/lib/systemd/system/ostree-prepare-root.service.d/armada-fallback.conf",
    "usr/lib/ostree/ostree-prepare-root",
)


def regular_file(path):
    require(path.is_file() and not path.is_symlink(), f"Expected regular file: {path}")


def check_archive_pin(archive):
    regular_file(archive)
    sidecar = Path(str(archive) + ".sha256")
    regular_file(sidecar)
    checksum = sidecar.read_text().split()
    require(len(checksum) == 2 and checksum[0].lower() == ARCHIVE_SHA256 and
            checksum[1] in {archive.name, "*" + archive.name}, "Archive sidecar differs from reviewed input")
    require(policy.sha256(archive) == ARCHIVE_SHA256, "Archive differs from reviewed SHA-256")


def validate_inventory(files):
    for name in files:
        require(re.fullmatch(r"[A-Za-z0-9_./+@-]+", name) is not None and
                not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts and
                name == PurePosixPath(name).as_posix(), f"Unsafe kernel filename: {name}")
        require(not any(str(parent) in files for parent in PurePosixPath(name).parents),
                f"File/directory collision in kernel archive: {name}")
    modules = {name for name in files if name.endswith(".ko")}
    dtbs = {name for name in files if name.endswith(".dtb")}
    require(len(modules) == 1619 and all(name.startswith("kernel/") for name in modules),
            "Expected exactly 1619 packaged kernel modules")
    require(len(dtbs) == 25 and all(name.startswith("dtb/qcom/") for name in dtbs),
            "Expected exactly 25 packaged Qualcomm DTBs")
    for name, digest in PINNED_FILES.items():
        require(files.get(name) == digest, f"Unexpected reviewed kernel component: {name}")
    return {"modules": len(modules), "dtbs": len(dtbs), "files": len(files)}


def package_verifier(inputs):
    verifier_path = inputs / "verify-kpfe-kernel-package.py"
    regular_file(verifier_path)
    require(policy.sha256(verifier_path) == VERIFIER_SHA256, "Original package verifier changed")
    verifier = load_module("reviewed_kernel_package", verifier_path)
    verifier.PATCH_SHA256 = PATCH_SHA256
    return verifier


def verify_package(archive=ARCHIVE, inputs=INPUTS):
    check_archive_pin(archive)
    verifier = package_verifier(inputs)
    report = verifier.verify(archive, inputs / "kernel")
    files, _ = verifier.read_package(archive)
    counts = validate_inventory(files)
    require(report["modules"] == counts["modules"] and len(report["dtbs_sha256"]) == counts["dtbs"],
            "Package verifier inventory differs")
    return report, files


def expected_report(files):
    counts = validate_inventory(files)
    require(all(name in files for name in METADATA), "Receipt is missing required kernel metadata")
    return {
        "status": "PASS", "scope": "package-consistency-only", "release": RELEASE,
        "archive_sha256": ARCHIVE_SHA256, "patch_0950_sha256": PATCH_SHA256,
        "vmlinuz_sha256": PINNED_FILES["vmlinuz"], "qcom_battmgr_sha256": PINNED_FILES[MODULE],
        "vermagic": VERMAGIC, "worker_symbols": list(WORKERS), "modules": counts["modules"],
        "dtbs_sha256": {PurePosixPath(name).name: digest for name, digest in files.items() if name.endswith(".dtb")},
        "metadata_sha256": {name: files[name] for name in METADATA}, "not_validated": NOT_VALIDATED,
    }


def package_receipt(archive, inputs):
    source_hashes = input_hashes(inputs)
    report, files = verify_package(archive, inputs)
    require(report == expected_report(files), "Full package verification report differs from pinned expectations")
    require(source_hashes == input_hashes(inputs), "Kernel build inputs changed during full verification")
    return {
        "schema_version": 1, "status": "PASS", "archive_sha256": ARCHIVE_SHA256,
        "patch_0950_sha256": PATCH_SHA256, "verifier_sha256": VERIFIER_SHA256,
        "producer_sha256": policy.sha256(Path(__file__)), "package_verification": report,
        "counts": validate_inventory(files), "files_sha256": files,
        "kernel_build_inputs_sha256": source_hashes,
    }


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, f"Duplicate verification receipt key: {name}")
        result[name] = value
    return result


def validate_receipt(receipt, source_hashes):
    fields = {"schema_version", "status", "archive_sha256", "patch_0950_sha256", "verifier_sha256",
              "producer_sha256", "package_verification", "counts", "files_sha256", "kernel_build_inputs_sha256"}
    require(isinstance(receipt, dict) and set(receipt) == fields and
            type(receipt["schema_version"]) is int and receipt["schema_version"] == 1,
            "Invalid package verification receipt schema")
    require(receipt["status"] == "PASS" and receipt["archive_sha256"] == ARCHIVE_SHA256 and
            receipt["patch_0950_sha256"] == PATCH_SHA256 and receipt["verifier_sha256"] == VERIFIER_SHA256 and
            receipt["producer_sha256"] == policy.sha256(Path(__file__)), "Stale or failed package verification receipt")
    require(receipt["kernel_build_inputs_sha256"] == source_hashes and
            source_hashes.get("verify-kpfe-kernel-package.py") == VERIFIER_SHA256 and
            source_hashes.get("kernel/patches/" + PATCH) == PATCH_SHA256,
            "Package verification receipt source inputs differ")
    files = receipt["files_sha256"]
    require(isinstance(files, dict) and files and
            all(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) for digest in files.values()),
            "Invalid package verification receipt file hashes")
    require(receipt["counts"] == validate_inventory(files) and
            receipt["package_verification"] == expected_report(files),
            "Package verification receipt report/inventory differs")
    return receipt["package_verification"], files


def load_verified_package(archive=ARCHIVE, inputs=INPUTS, receipt_path=VERIFICATION_PATH):
    regular_file(receipt_path)
    receipt = json.loads(receipt_path.read_text(), object_pairs_hook=unique_object)
    check_archive_pin(archive)
    report, files = validate_receipt(receipt, input_hashes(inputs))
    actual, _ = package_verifier(inputs).read_package(archive)
    validate_inventory(actual)
    require(actual == files, "Current archive inventory differs from full verification receipt")
    return report, files


@contextmanager
def package_stream(archive):
    process = subprocess.Popen(["zstd", "-dc", "--", str(archive)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as package:
            yield package
        while process.stdout.read(1024 * 1024):
            pass
        require(process.wait() == 0, "zstd integrity/decompression check failed")
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.terminate()
            process.wait()


def validate_member(member, seen):
    name = member.name.rstrip("/") if member.isdir() else member.name
    path = PurePosixPath(name)
    require(name and name == path.as_posix() and not path.is_absolute() and
            ".." not in path.parts and re.fullmatch(r"[A-Za-z0-9_./+@-]+", name),
            f"Unsafe archive path: {name!r}")
    require(name not in seen, f"Duplicate archive member: {name}")
    seen.add(name)
    require(member.isdir() or (member.isfile() and member.sparse is None),
            f"Link or special archive member: {name}")
    require(member.uid == member.gid == 0 and not member.mode & 0o7000,
            f"Unexpected archive ownership or special permissions: {name}")
    require(name in {"lib", "lib/modules", PREFIX[:-1]} or name.startswith(PREFIX),
            f"Unexpected package path or kernel release: {name}")
    require(not path.name.lower().startswith(("initrd", "initramfs")) and path.name != "KERNEL",
            f"Boot image/initramfs in package: {name}")
    require(member.isdir() or (name.startswith(PREFIX) and member.size > 0),
            f"Empty file or file outside release directory: {name}")
    return name[len(PREFIX):] if name.startswith(PREFIX) else None


def extract_verified(archive, destination, files):
    require(destination.is_dir() and not destination.is_symlink() and not any(destination.iterdir()),
            "Kernel staging directory must be empty and regular")
    seen, extracted = set(), {}
    with package_stream(archive) as package:
        for member in package:
            relative = validate_member(member, seen)
            if not relative:
                continue
            path = destination / relative
            if member.isdir():
                require(relative not in files, f"File/directory collision: {relative}")
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(0o755)
                continue
            require(relative in files, f"Unverified archive file: {relative}")
            path.parent.mkdir(parents=True, exist_ok=True)
            with package.extractfile(member) as source, path.open("xb") as target:
                shutil.copyfileobj(source, target)
            path.chmod(member.mode)
            extracted[relative] = policy.sha256(path)
            require(extracted[relative] == files[relative], f"Archive changed while extracting: {relative}")
    require(extracted == files, "Extracted kernel differs from verified archive")
    destination.chmod(0o755)


def validate_target(root=Path("/")):
    require(root.is_absolute() and root.resolve() == root, "Kernel root must be canonical")
    for name in ("/usr", "/usr/lib", "/usr/lib/modules", TARGET):
        path = policy.path_at(root, name)
        require(path.is_dir() and not path.is_symlink(), f"Unsafe kernel replacement target: {path}")
    parent = policy.path_at(root, "/usr/lib/modules")
    require({child.name for child in parent.iterdir()} == {RELEASE}, "Unexpected installed kernel releases")
    return parent / RELEASE


def replace_tree(archive, files, root=Path("/")):
    target = validate_target(root)
    with tempfile.TemporaryDirectory(prefix=".scoped-kernel-", dir=target.parent) as temporary:
        stage = Path(temporary)
        replacement = stage / RELEASE
        replacement.mkdir()
        extract_verified(archive, replacement, files)
        previous = stage / "previous"
        try:
            target.rename(previous)
        except OSError as error:
            if error.errno != errno.EXDEV:
                raise
            shutil.copytree(target, previous, symlinks=True)
            shutil.rmtree(target)
        try:
            replacement.rename(target)
        except OSError:
            previous.rename(target)
            raise
    validate_target(root)


def verify_protected_delta(before, after):
    def protected(snapshot):
        return {name: metadata for name, metadata in snapshot.items()
                if name != TARGET and not name.startswith(TARGET + "/")}
    old, new = protected(before), protected(after)
    changed = sorted(name for name in old.keys() | new.keys() if old.get(name) != new.get(name)
                     or (name in old) != (name in new))
    require(not changed, f"Protected paths changed outside exact kernel tree: {changed}")


def verify_installed(files, root=Path("/"), *, regenerated=False):
    target = validate_target(root)
    actual = {}
    for path in policy.walk(target):
        metadata = path.lstat()
        require((stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)) and
                metadata.st_uid == metadata.st_gid == 0 and not metadata.st_mode & 0o7000,
                f"Invalid installed kernel type/ownership/mode: {path}")
        if path.is_file():
            actual[str(path.relative_to(target))] = policy.sha256(path)
    allowed = DEPMOD_FILES | {"initramfs.img"} if regenerated else set()
    require(not (set(files) - set(actual)) and not (set(actual) - set(files) - allowed),
            "Installed kernel contains missing or unreviewed files")
    for name, digest in files.items():
        require(regenerated and name in DEPMOD_FILES or actual[name] == digest,
                f"Installed kernel file differs from archive: {name}")
    if regenerated:
        require("initramfs.img" in actual and (target / "initramfs.img").stat().st_size > 0,
                "Regenerated initramfs is missing or empty")
    return actual


def initramfs_listing(output, files):
    helpers, modules = set(), {}
    for line in output.splitlines():
        if not re.match(r"^[-dlbcps][rwxStTs-]{9}\s", line):
            continue
        path = line.split(" -> ", 1)[0].split()[-1]
        if path in BOOT_HELPERS:
            require(line.startswith("-") and path not in helpers, f"Invalid/duplicate initramfs helper: {path}")
            helpers.add(path)
        if ".ko" not in path:
            continue
        match = re.fullmatch(r"(?:usr/)?lib/modules/7\.2\.3/(kernel/.+\.ko)(?:\.(xz|gz|zst))?", path)
        require(match is not None and line.startswith("-") and " -> " not in line,
                f"Unexpected initramfs module path/type: {path}")
        require(match[1] in files and path not in modules and
                match[1] not in {item[0] for item in modules.values()},
                f"Unreviewed or duplicate initramfs module: {path}")
        modules[path] = (match[1], match[2])
    require(helpers == set(BOOT_HELPERS), f"Missing initramfs boot helpers: {sorted(set(BOOT_HELPERS) - helpers)}")
    require(bool(modules), "Initramfs contains no listed kernel modules")
    return modules


def module_digest(path, compression):
    if compression == "zst":
        result = subprocess.run(["zstd", "-dc", "--", str(path)], capture_output=True, check=True)
        return hashlib.sha256(result.stdout).hexdigest()
    opener = {"xz": lzma.open, "gz": gzip.open, None: open}[compression]
    with opener(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_initramfs(files, root=Path("/")):
    initramfs = policy.path_at(root, TARGET + "/initramfs.img")
    regular_file(initramfs)
    listing = policy.run(["lsinitrd", str(initramfs)]).stdout
    modules = initramfs_listing(listing, files)
    patterns = sorted({path.split("/kernel/", 1)[0] + "/kernel/*.ko*" for path in modules})
    with tempfile.TemporaryDirectory(prefix="scoped-initramfs-check-") as temporary:
        result = subprocess.run(["lsinitrd", "--unpack", str(initramfs), *patterns],
                                cwd=temporary, capture_output=True, text=True,
                                env={**os.environ, "LC_ALL": "C", "SYSTEMD_OFFLINE": "1"})
        require(result.returncode == 0, f"Cannot inspect initramfs modules: {result.stderr}")
        extracted = {}
        for path in policy.walk(Path(temporary)):
            require(not path.is_symlink() and (path.is_dir() or path.is_file()),
                    f"Unexpected extracted initramfs member: {path}")
            if path.is_file():
                name = str(path.relative_to(temporary))
                require(name in modules, f"Unlisted initramfs module: {name}")
                relative, compression = modules[name]
                extracted[name] = module_digest(path, compression)
                require(extracted[name] == files[relative], f"Stale or unexpected initramfs module: {name}")
        require(set(extracted) == set(modules), "Listed initramfs modules were not all extracted")
    present = any(relative == MODULE for relative, _ in modules.values())
    return {"sha256": policy.sha256(initramfs), "listing_sha256": hashlib.sha256(listing.encode()).hexdigest(),
            "boot_helpers": list(BOOT_HELPERS), "modules_checked": len(modules),
            "module_sha256": extracted, "qcom_battmgr_present": present,
            "qcom_battmgr_sha256": files[MODULE] if present else None}


def input_hashes(inputs=INPUTS):
    hashes = {}
    for path in policy.walk(inputs):
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), f"Invalid kernel build input: {path}")
        if path.is_file():
            hashes[str(path.relative_to(inputs))] = policy.sha256(path)
    require(bool(hashes), "Kernel build input set is empty")
    return hashes


def install():
    policy.verify_environment()
    policy.verify_kernel()
    policy.verify_disabled()
    require(not os.path.lexists(EVIDENCE_PATH), "Kernel image evidence already exists")
    regular_file(policy.EVIDENCE_PATH)
    package_evidence = json.loads(policy.EVIDENCE_PATH.read_text())
    require(package_evidence.get("base_image") == policy.BASE_IMAGE and
            package_evidence.get("result") == "disabled-image-transaction-verified" and
            package_evidence.get("kernel_rebuilt") is False and package_evidence.get("charging_enabled") is False,
            "Verified disabled package transaction must precede kernel replacement")
    regular_file(HELPER)
    require(policy.sha256(HELPER) == HELPER_SHA256, "Existing initramfs helper changed")
    source_hashes = input_hashes()
    report, files = load_verified_package()
    receipt_sha256 = policy.sha256(VERIFICATION_PATH)
    protected_paths = (*policy.PROTECTED_PATHS, *policy.INTEGRATION_FILES,
                       "/usr/lib/systemd/system/armada-charging.service", str(policy.EVIDENCE_PATH))
    before = policy.snapshot(names=protected_paths)
    enabled = policy.enablement_snapshot()
    packages = policy.parse_inventory(policy.run(["rpm", "-qa", "--qf", policy.QUERY_FORMAT]).stdout)
    require(sorted(list(item) for item in packages.elements()) == package_evidence["packages_after"],
            "Installed packages differ from verified package transaction")
    replace_tree(ARCHIVE, files)
    verify_installed(files)
    policy.run(["depmod", "-a", RELEASE, "-b", "/"])
    result = policy.run(["bash", str(HELPER)])
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    installed = verify_installed(files, regenerated=True)
    initramfs = verify_initramfs(files)
    after = policy.snapshot(names=protected_paths)
    verify_protected_delta(before, after)
    require(policy.enablement_snapshot() == enabled, "Systemd enablement changed during kernel operation")
    require(policy.parse_inventory(policy.run(["rpm", "-qa", "--qf", policy.QUERY_FORMAT]).stdout) == packages,
            "RPM inventory changed during kernel operation")
    policy.verify_disabled()
    require(source_hashes == input_hashes(), "Kernel build inputs changed during installation")
    require(policy.sha256(VERIFICATION_PATH) == receipt_sha256, "Package verification receipt changed during installation")
    evidence = {
        "schema_version": 1, "result": "disabled-scoped-kernel-image-verified",
        "base_image": policy.BASE_IMAGE, "release": RELEASE, "archive_sha256": ARCHIVE_SHA256,
        "archive_manifest_sha256": policy.manifest_digest(files), "package_verification": report,
        "counts": validate_inventory(files), "installed_sha256": installed, "initramfs": initramfs,
        "kernel_build_inputs_sha256": source_hashes,
        "package_verification_receipt_sha256": receipt_sha256,
        "image_build_inputs_sha256": {str(path): policy.sha256(path) for path in
                                      (Path(__file__), POLICY_PATH, HELPER)},
        "package_evidence_sha256": policy.sha256(policy.EVIDENCE_PATH),
        "protected_paths": list(protected_paths), "protected_entries": len(before),
        "protected_before_sha256": policy.manifest_digest(before),
        "protected_after_sha256": policy.manifest_digest(after),
        "allowed_changed_tree": TARGET, "enablement_sha256": policy.manifest_digest(enabled),
        "packages": sorted(list(item) for item in packages.elements()),
        "rpm_inventory_unchanged": True, "enablement_unchanged": True,
        "firmware_boot_machinery_system_configuration_unchanged": True,
        "kernel_replaced": True, "kernel_compiled_in_image_build": False, "initramfs_regenerated": True,
        "charging_enabled": False, "hardware_validated": False, "enablement_receipt": "not-generated",
        "not_validated": NOT_VALIDATED,
    }
    with EVIDENCE_PATH.open("x") as stream:
        json.dump(evidence, stream, indent=2, sort_keys=True)
        stream.write("\n")
    EVIDENCE_PATH.chmod(0o644)
    print(f"Verified disabled scoped kernel image: {EVIDENCE_PATH}")


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-package", nargs=2, type=Path, metavar=("ARCHIVE", "INPUTS"),
                        help="run full package verification on the build runner and emit its receipt")
    args = parser.parse_args(arguments)
    if args.verify_package:
        print(json.dumps(package_receipt(*args.verify_package), indent=2, sort_keys=True))
    else:
        install()


if __name__ == "__main__":
    try:
        main()
    except (VerificationError, OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        sys.exit(f"Scoped kernel image verification failed: {error}")
