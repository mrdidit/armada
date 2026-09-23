#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Install the reviewed, disabled charging RPMs in the pinned build container."""

import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys


BASE_IMAGE = "ghcr.io/mrdidit/armada@sha256:3ad2d5de4575d8fffacc92a77aae6a382f9a0066818f5f99e8de3d35cb26313c"
SOURCE_REVISION = "543a4f12bd834897a9ec577c7a485080b19ca1df"
BUILD_ID = "35854292032"
RPM_DIRECTORY = Path("/charging-rpms")
EVIDENCE_PATH = Path("/usr/share/armada-charging/image-verification.json")
QUERY_FORMAT = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n"
PACKAGES = {
    "powerdevil": (
        "powerdevil-6.7.4-2.fc44.armada.charging.b35854292032.aarch64.rpm",
        "46dd088fabce1ef3297fcc2cec06741c3c44b4f76685c29549295cc6c4b991e8",
        ("powerdevil", "0", "6.7.4", "2.fc44.armada.charging.b35854292032", "aarch64"),
    ),
    "upower": (
        "upower-1.91.4-1.fc44.armada.charging.b35854292032.aarch64.rpm",
        "eb67753a1ee8e9c39c340cc584b02d1b459c1c4c2e53f415e790b03112546edf",
        ("upower", "0", "1.91.4", "1.fc44.armada.charging.b35854292032", "aarch64"),
    ),
    "upower-libs": (
        "upower-libs-1.91.4-1.fc44.armada.charging.b35854292032.aarch64.rpm",
        "a53735d1645c62cc1f3ad17004ed4f5249b04e9b375d0785bcec7c897201d6f3",
        ("upower-libs", "0", "1.91.4", "1.fc44.armada.charging.b35854292032", "aarch64"),
    ),
    "armada-charging": (
        "armada-charging-0.1.0-1.fc44.armada.charging.b35854292032.noarch.rpm",
        "da069a3acc0ad91bd2941522c0c829bdab92fbe963f27f681e186efb8427633a",
        ("armada-charging", "0", "0.1.0", "1.fc44.armada.charging.b35854292032", "noarch"),
    ),
}
BASE_PACKAGES = {
    ("powerdevil", "0", "6.7.4", "2.fc44.armada", "aarch64"),
    ("upower", "0", "1.91.4", "1.fc44", "aarch64"),
    ("upower-libs", "0", "1.91.4", "1.fc44", "aarch64"),
}
PROTECTED_PATHS = (
    "/etc", "/boot", "/usr/lib/modules", "/usr/lib/firmware",
    "/usr/lib/armada", "/usr/libexec/armada", "/usr/lib/ostree",
    "/usr/lib/dracut", "/usr/lib/kernel", "/usr/lib/bootc", "/usr/lib/bootupd",
    "/usr/lib/systemd/system/ostree-finalize-staged.service",
    "/usr/lib/systemd/system/ostree-finalize-staged.service.d",
    "/usr/lib/systemd/system/armada-bootimg-sync.service",
    "/usr/lib/systemd/system/armada-esp-rename.service",
    "/usr/lib/systemd/system/bootc-generic-growpart.service.d",
)
SYSTEMD_PATHS = (
    "/etc/systemd/system", "/etc/systemd/user",
    "/usr/lib/systemd/system", "/usr/lib/systemd/user",
    "/run/systemd/system", "/run/systemd/user",
)
NEW_CONFIG_PATHS = {
    "/etc/armada-charging", "/etc/armada-charging/devices.json",
    "/etc/armada-charging/ownership.json",
}
INTEGRATION_FILES = (
    "/usr/libexec/kf6/kauth/chargethresholdhelper", "/usr/libexec/upowerd",
    "/usr/libexec/armada-charging-kde", "/usr/bin/armada-charging",
    "/usr/lib/armada-charging/armada_charging.py",
    "/usr/lib/armada-charging/armada_charging_desktop.py",
    "/usr/lib/armada-charging/armada_charging_ownership.py",
    "/usr/lib/armada-charging/armada_charging_loader.py",
)
KERNEL_FILES = {
    "/usr/lib/modules/7.2.3/vmlinuz": "129771171db1f8300c16755522fdb6c58e5787116334201f1bbffdc8555b889a",
    "/usr/lib/modules/7.2.3/kernel/drivers/power/supply/qcom_battmgr.ko": "3e4b628545bfbafc402a5d8a0deaf5d412349430c6c7d32ee28beb5ef5d6cde9",
    "/usr/lib/modules/7.2.3/dtb/qcom/sm8750-konkr-pf-elite.dtb": "36f7c276ebd156c0dbfe86dd6092ea9d6b365759698383088554a86178fc72b7",
}


class VerificationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(arguments, *, check=True):
    result = subprocess.run(arguments, text=True, capture_output=True,
                            env={**os.environ, "LC_ALL": "C", "SYSTEMD_OFFLINE": "1"})
    if check and result.returncode:
        raise VerificationError(f"Command failed: {arguments!r}\n{result.stdout}{result.stderr}")
    return result


def path_at(root, name):
    return root / name.lstrip("/")


def walk(path):
    yield path
    if path.is_dir() and not path.is_symlink():
        for child in sorted(path.iterdir()):
            yield from walk(child)


def entry(path):
    metadata = path.lstat()
    result = {
        "mode": metadata.st_mode, "uid": metadata.st_uid, "gid": metadata.st_gid,
        "xattrs": {name: base64.b64encode(os.getxattr(path, name, follow_symlinks=False)).decode()
                   for name in sorted(os.listxattr(path, follow_symlinks=False))},
    }
    if stat.S_ISREG(metadata.st_mode):
        result["sha256"] = sha256(path)
    elif stat.S_ISLNK(metadata.st_mode):
        result["target"] = os.readlink(path)
    elif not stat.S_ISDIR(metadata.st_mode):
        result["rdev"] = metadata.st_rdev
    return result


def snapshot(root=Path("/"), names=PROTECTED_PATHS):
    result = {}
    for name in names:
        path = path_at(root, name)
        if not os.path.lexists(path):
            result[name] = None
            continue
        for child in walk(path):
            result["/" + str(child.relative_to(root))] = entry(child)
    return result


def enablement_snapshot(root=Path("/")):
    result = {}
    for name in SYSTEMD_PATHS:
        path = path_at(root, name)
        if not os.path.lexists(path):
            result[name] = None
            continue
        for child in walk(path):
            relative = "/" + str(child.relative_to(root))
            if child.is_symlink() or any(part.endswith((".wants", ".requires", ".upholds"))
                                         for part in child.parts):
                result[relative] = entry(child)
    return result


def verify_snapshots(before, after):
    require(not NEW_CONFIG_PATHS.intersection(before), "Charging configuration already existed")
    require(set(after) - set(before) == NEW_CONFIG_PATHS,
            f"Unexpected protected additions: {sorted(set(after) - set(before))}")
    removed = set(before) - set(after)
    changed = [name for name in before if name in after and before[name] != after[name]]
    require(not removed and not changed,
            f"Protected paths changed: removed={sorted(removed)}, changed={sorted(changed)}")


def parse_inventory(output):
    result = Counter()
    for line in output.splitlines():
        fields = tuple(line.split("\t"))
        require(len(fields) == 5 and all(fields) and fields[1].isdigit(), "Malformed RPM inventory")
        result[fields] += 1
    require(bool(result), "Empty RPM inventory")
    return result


def verify_base_inventory(before):
    selected = Counter({item: count for item, count in before.items() if item[0] in PACKAGES})
    require(selected == Counter(BASE_PACKAGES), "Installed package baseline differs from the reviewed image")


def verify_inventory(before, after):
    verify_base_inventory(before)
    expected = before.copy()
    expected.subtract(Counter(BASE_PACKAGES))
    expected += Counter(item[2] for item in PACKAGES.values())
    require(after == expected, "RPM inventory changed outside the three replacements and one addition")


def verify_inputs(directory=RPM_DIRECTORY):
    require(directory.is_dir() and not directory.is_symlink(), "Missing regular RPM input directory")
    require({path.name for path in directory.iterdir()} == {item[0] for item in PACKAGES.values()},
            "RPM input directory must contain exactly the four reviewed RPMs")
    paths = []
    for filename, digest, identity in PACKAGES.values():
        path = directory / filename
        require(path.is_file() and not path.is_symlink(), f"Invalid RPM input: {filename}")
        require(sha256(path) == digest, f"RPM checksum mismatch: {filename}")
        actual = parse_inventory(run(["rpm", "-qp", "--qf", QUERY_FORMAT, str(path)]).stdout)
        require(actual == Counter({identity: 1}), f"Unexpected RPM identity: {filename}")
        paths.append(str(path))
    return paths


def verify_environment(root=Path("/")):
    require(os.geteuid() == 0 and platform.machine() == "aarch64", "Requires a root, native ARM64 build container")
    require(any(path_at(root, name).is_file() for name in ("/run/.containerenv", "/.dockerenv")),
            "A build-container marker is required")
    for name in ("/run/ostree-booted", "/run/systemd/system", "/run/dbus/system_bus_socket"):
        require(not os.path.lexists(path_at(root, name)), f"Refusing host/service access: {name}")


def verify_kernel(root=Path("/")):
    modules = path_at(root, "/usr/lib/modules")
    require(modules.is_dir() and not modules.is_symlink() and
            {child.name for child in modules.iterdir()} == {"7.2.3"} and
            not (modules / "7.2.3").is_symlink(),
            "Expected exactly the retained Linux 7.2.3 kernel")
    for name in ("/usr/lib/firmware", "/usr/lib/armada", "/usr/libexec/armada"):
        path = path_at(root, name)
        require(path.is_dir() and not path.is_symlink(), f"Invalid protected directory: {name}")
    for name, expected in KERNEL_FILES.items():
        require(sha256(path_at(root, name)) == expected, f"Unexpected base kernel component: {name}")
    for name in ("/usr/lib/modules/7.2.3/initramfs.img", "/usr/libexec/armada/mkbootimg.py",
                 "/usr/libexec/armada/armada-bootimg-update", "/usr/libexec/armada/armada-bootimg-finalize",
                 "/usr/lib/armada/bootimg-args", "/usr/lib/armada/supported-dtbs"):
        path = path_at(root, name)
        require(path.is_file() and path.stat().st_size > 0, f"Missing retained boot component: {name}")


def verify_disabled(root=Path("/"), *, installed=True):
    for name in ("/etc/armada-charging/managed.d", "/var/lib/armada-charging", "/run/armada-charging"):
        require(not os.path.lexists(path_at(root, name)), f"Unexpected charging enrollment/state: {name}")
    for name in SYSTEMD_PATHS:
        directory = path_at(root, name)
        if not os.path.lexists(directory):
            continue
        for path in walk(directory):
            vendor_unit = path_at(root, "/usr/lib/systemd/system/armada-charging.service")
            reserved = path.name == "armada-charging.service" and path != vendor_unit
            linked = path.is_symlink() and Path(os.readlink(path)).name == "armada-charging.service"
            require(not reserved and not linked, f"Charging unit is enabled/overridden: {path}")
    config = path_at(root, "/etc/armada-charging")
    if not installed:
        require(not os.path.lexists(config), "Charging policy must not already be installed")
        return
    require(config.is_dir() and not config.is_symlink(), "Invalid charging configuration directory")
    require({path.name for path in config.iterdir()} == {"devices.json", "ownership.json"},
            "Unexpected charging configuration files")
    documents = {}
    for filename in ("devices.json", "ownership.json"):
        path = config / filename
        require(path.is_file() and not path.is_symlink(), f"Invalid configuration file: {filename}")
        documents[filename] = json.loads(path.read_text())
        require(isinstance(documents[filename], dict) and
                type(documents[filename].get("schema_version")) is int and
                documents[filename]["schema_version"] == 1, "Invalid charging configuration schema")
    devices = documents["devices.json"]
    require(set(devices) == {"schema_version", "devices"} and isinstance(devices["devices"], list) and
            len(devices["devices"]) == 1, "Unexpected device support metadata")
    device = devices["devices"][0]
    require(device == {"compatible": "konkr,pocket-fit-elite", "backend": "kpfe-qcom-battmgr",
                       "implemented": True, "validated": False, "lifecycle_validated": False} and
            device["implemented"] is True and device["validated"] is False and
            device["lifecycle_validated"] is False, "Device validation gates are not disabled")
    ownership = documents["ownership.json"]
    require(ownership == {"schema_version": 1, "exclusive_control": False, "integration_ready": False,
                          "review_reference": "", "integration": "kde-shared-policy-v1",
                          "development": None, "files": {}} and
            ownership["exclusive_control"] is False and ownership["integration_ready"] is False,
            "Ownership/development gates are not disabled")
    unit = path_at(root, "/usr/lib/systemd/system/armada-charging.service")
    require(unit.is_file() and not unit.is_symlink(), "Missing regular charging unit")


def verify_rpm_files(result, before, after):
    require(result.returncode in (0, 1) and not result.stderr.strip(), "RPM payload verification failed")
    preserved = []
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"[.A-Z5?]{9}\s+c\s+(/etc/\S.*)", line)
        require(match is not None, f"Unexpected RPM verification difference: {line}")
        name = match[1]
        require(name in before and before[name] is not None and before[name] == after.get(name),
                f"RPM configuration difference was not preserved from the base: {name}")
        preserved.append(line)
    require(result.returncode == 0 or bool(preserved), "RPM verification failed without diagnostic output")
    return preserved


def manifest_digest(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def install():
    verify_environment()
    verify_kernel()
    verify_disabled(installed=False)
    require(not os.path.lexists(EVIDENCE_PATH), "Image verification evidence already exists")
    paths = verify_inputs()
    before_packages = parse_inventory(run(["rpm", "-qa", "--qf", QUERY_FORMAT]).stdout)
    verify_base_inventory(before_packages)
    before = snapshot()
    enabled_before = enablement_snapshot()
    run(["rpm", "-Uvh", "--test", *paths])
    result = run(["rpm", "-Uvh", *paths])
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    run(["rpmdb", "--verifydb"])
    after_packages = parse_inventory(run(["rpm", "-qa", "--qf", QUERY_FORMAT]).stdout)
    verify_inventory(before_packages, after_packages)
    after = snapshot()
    verify_snapshots(before, after)
    require(enablement_snapshot() == enabled_before, "Systemd enablement changed")
    verify_disabled()
    preserved = verify_rpm_files(run(["rpm", "-V", *PACKAGES], check=False), before, after)
    evidence = {
        "schema_version": 1, "base_image": BASE_IMAGE, "package_build_id": BUILD_ID,
        "package_source_revision": SOURCE_REVISION, "result": "disabled-image-transaction-verified",
        "rpms": {item[0]: item[1] for item in PACKAGES.values()},
        "packages_before": sorted(list(item) for item in before_packages.elements()),
        "packages_after": sorted(list(item) for item in after_packages.elements()),
        "protected_paths": list(PROTECTED_PATHS), "protected_entries": len(before),
        "protected_sha256": manifest_digest(before), "enablement_sha256": manifest_digest(enabled_before),
        "preserved_config_verification": preserved,
        "integration_files": {name: sha256(Path(name)) for name in INTEGRATION_FILES},
        "kernel_files": {name: sha256(Path(name)) for name in (*KERNEL_FILES, "/usr/lib/modules/7.2.3/initramfs.img")},
        "kernel_rebuilt": False, "initramfs_regenerated": False, "charging_enabled": False,
        "hardware_validated": False, "enablement_receipt": "not-generated",
    }
    EVIDENCE_PATH.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with EVIDENCE_PATH.open("x") as stream:
        json.dump(evidence, stream, indent=2, sort_keys=True)
        stream.write("\n")
    EVIDENCE_PATH.chmod(0o644)
    print(f"Verified disabled charging image: {EVIDENCE_PATH}")


if __name__ == "__main__":
    try:
        install()
    except (VerificationError, OSError, ValueError) as error:
        sys.exit(f"Charging image verification failed: {error}")
