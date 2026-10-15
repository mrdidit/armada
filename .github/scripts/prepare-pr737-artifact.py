#!/usr/bin/env python3
"""Validate and download one pinned PR 737 OCI artifact; never execute its files."""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import zipfile


UPSTREAM = "armada-os/armada"
FORK = "mrdidit/armada"
BRANCH = "feat/kpfe-steam-recording"
IMAGE = "ghcr.io/mrdidit/armada"
ARTIFACT_NAME = "armada-container-pr737"
ARCHIVE_NAME = "armada-pr-737.tar"
MAX_ARCHIVE_BYTES = 64 * 1024**3


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inputs(environ):
    result = {}
    for field in ("RUN_ID", "RUN_ATTEMPT", "ARTIFACT_ID"):
        value = environ.get("PR737_" + field, "")
        require(re.fullmatch(r"[1-9][0-9]{0,19}", value), f"Invalid {field}")
        result[field.lower()] = int(value)
    for field, length in (("HEAD_SHA", 40), ("MERGE_SHA", 40), ("TREE_SHA", 40),
                          ("ARTIFACT_SHA256", 64)):
        value = environ.get("PR737_" + field, "")
        require(re.fullmatch(rf"[0-9a-f]{{{length}}}", value), f"Invalid {field}")
        result[field.lower()] = value
    return result


def command(args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE).stdout


def api(path):
    try:
        return json.loads(command(["gh", "api", f"repos/{UPSTREAM}/{path}"]))
    except subprocess.CalledProcessError as exc:
        raise ValueError("Cannot read the pinned upstream run/artifact with this token; "
                         "no image was published. Cross-repository Actions read access "
                         "must be available.") from exc


def validate_metadata(values, run, attempt, workflow, pr, head, merge, artifact, jobs):
    for item in (run, attempt):
        require(item.get("id") == values["run_id"], "Run ID mismatch")
        require(item.get("run_attempt") == values["run_attempt"], "Run attempt changed")
        require(item.get("status") == "completed" and item.get("conclusion") == "success",
                "The exact upstream run must have completed successfully")
        require(item.get("event") == "pull_request", "Not a pull_request build")
        require(item.get("path") == ".github/workflows/pr.yml", "Unexpected build workflow")
        require(item.get("repository", {}).get("full_name") == UPSTREAM,
                "Unexpected build repository")
        require(item.get("head_repository", {}).get("full_name") == FORK,
                "Unexpected head repository")
        require(item.get("head_branch") == BRANCH and item.get("head_sha") == values["head_sha"],
                "Run is not for the expected PR head")
    require(workflow.get("id") == run.get("workflow_id")
            and workflow.get("id") == attempt.get("workflow_id")
            and workflow.get("path") == ".github/workflows/pr.yml", "Workflow ID mismatch")
    require(pr.get("number") == 737 and pr.get("state") == "open", "PR 737 is not open")
    require(pr.get("head", {}).get("repo", {}).get("full_name") == FORK
            and pr["head"].get("ref") == BRANCH
            and pr["head"].get("sha") == values["head_sha"], "PR head changed")
    require(pr.get("base", {}).get("repo", {}).get("full_name") == UPSTREAM
            and pr["base"].get("ref") == "main", "Unexpected PR base")
    require(pr.get("merge_commit_sha") == values["merge_sha"], "PR merge commit changed")
    require(head.get("sha") == values["head_sha"]
            and head.get("tree", {}).get("sha") == values["tree_sha"], "Head tree mismatch")
    require(merge.get("sha") == values["merge_sha"]
            and merge.get("tree", {}).get("sha") == values["tree_sha"], "Merge tree mismatch")
    require([p.get("sha") for p in merge.get("parents", [])]
            == [pr["base"].get("sha"), values["head_sha"]], "Unexpected merge parents")
    require(artifact.get("id") == values["artifact_id"]
            and artifact.get("name") == ARTIFACT_NAME
            and artifact.get("expired") is False, "Unexpected or expired artifact")
    require(artifact.get("digest") == "sha256:" + values["artifact_sha256"],
            "Artifact ZIP digest missing or mismatched")
    origin = artifact.get("workflow_run", {})
    require(origin.get("id") == values["run_id"]
            and origin.get("head_sha") == values["head_sha"]
            and origin.get("head_branch") == BRANCH, "Artifact source mismatch")
    require(isinstance(artifact.get("size_in_bytes"), int)
            and 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE_BYTES,
            "Invalid or excessive artifact size")
    created = datetime.fromisoformat(artifact.get("created_at", "").replace("Z", "+00:00"))
    started = datetime.fromisoformat(attempt.get("run_started_at", "").replace("Z", "+00:00"))
    completed = datetime.fromisoformat(attempt.get("updated_at", "").replace("Z", "+00:00"))
    require(created.tzinfo is not None and started.tzinfo is not None
            and completed.tzinfo is not None and started <= created <= completed,
            "Artifact was not created during the selected run attempt")
    require(jobs.get("total_count") == len(jobs.get("jobs", [])), "Incomplete attempt job list")
    image_jobs = [job for job in jobs["jobs"] if job.get("name") == "Container image"]
    require(len(image_jobs) == 1, "Expected exactly one image job in the selected attempt")
    job = image_jobs[0]
    require(job.get("run_id") == values["run_id"]
            and job.get("run_attempt") == values["run_attempt"]
            and job.get("status") == "completed" and job.get("conclusion") == "success",
            "Image job did not succeed in the selected attempt")
    uploads = [step for step in job.get("steps", []) if step.get("name") == "Upload container image"]
    require(len(uploads) == 1 and uploads[0].get("status") == "completed"
            and uploads[0].get("conclusion") == "success", "Container artifact upload did not succeed")
    upload_start = datetime.fromisoformat(uploads[0].get("started_at", "").replace("Z", "+00:00"))
    upload_end = datetime.fromisoformat(uploads[0].get("completed_at", "").replace("Z", "+00:00"))
    require(upload_start.tzinfo is not None and upload_end.tzinfo is not None
            and upload_start <= created <= upload_end,
            "Artifact creation does not match the selected attempt's upload step")


def verify_zip(archive, expected_digest):
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    require(digest == expected_digest, "Downloaded artifact ZIP checksum mismatch")
    with zipfile.ZipFile(archive) as zipped:
        members = zipped.infolist()
        require(len(members) == 1 and members[0].filename == ARCHIVE_NAME,
                "Artifact must contain exactly the expected OCI archive")
        member = members[0]
        mode = member.external_attr >> 16
        require(not member.is_dir() and not stat.S_ISLNK(mode)
                and not member.flag_bits & 1, "Unexpected archive member type")
        require(0 < member.file_size <= MAX_ARCHIVE_BYTES, "Invalid OCI archive size")
        require(shutil.disk_usage(archive.parent).free > member.file_size + 1024**3,
                "Insufficient disk space to extract the OCI archive")
        target = archive.parent / ARCHIVE_NAME
        with zipped.open(member) as source, target.open("xb") as destination:
            shutil.copyfileobj(source, destination, length=1024**2)
        require(target.stat().st_size == member.file_size, "OCI archive size mismatch")
    return target


def validate_oci(values, config, manifest):
    labels = config.get("config", {}).get("Labels", {})
    require(config.get("architecture") == "arm64" and config.get("os") == "linux",
            "Artifact is not a Linux ARM64 image")
    require(config.get("config", {}).get("Cmd") == ["/sbin/init"], "Unexpected image command")
    require(labels.get("org.opencontainers.image.revision") == values["merge_sha"],
            "Image revision does not match the verified merge commit")
    require(re.fullmatch(r"[0-9]{8}\." + values["merge_sha"][:7],
                         labels.get("org.opencontainers.image.version", "")),
            "Unexpected image version")
    require(labels.get("containers.bootc") == "1" and labels.get("ostree.bootable") == "true",
            "Image lacks required bootc metadata")
    for data in (labels, manifest.get("annotations", {})):
        require("ostree.commit" not in data and "ostree.final-diffid" not in data,
                "Image has stale OSTree annotations")
    layers = manifest.get("layers", [])
    require(manifest.get("schemaVersion") == 2 and 1 < len(layers) <= 128,
            "Unexpected manifest or layer count")
    for blob in [manifest.get("config", {}), *layers]:
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", blob.get("digest", ""))
                and isinstance(blob.get("size"), int) and blob["size"] > 0
                and not blob.get("urls"), "Invalid or externally referenced OCI blob")


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    values = inputs(os.environ)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    evidence = output / "evidence"
    evidence.mkdir()
    run = api(f"actions/runs/{values['run_id']}")
    attempt = api(f"actions/runs/{values['run_id']}/attempts/{values['run_attempt']}")
    workflow_id = run.get("workflow_id")
    require(isinstance(workflow_id, int) and workflow_id > 0, "Invalid workflow ID")
    workflow = api(f"actions/workflows/{workflow_id}")
    pr = api("pulls/737")
    head = api(f"git/commits/{values['head_sha']}")
    merge = api(f"git/commits/{values['merge_sha']}")
    artifact = api(f"actions/artifacts/{values['artifact_id']}")
    jobs = api(f"actions/runs/{values['run_id']}/attempts/{values['run_attempt']}/jobs?per_page=100")
    validate_metadata(values, run, attempt, workflow, pr, head, merge, artifact, jobs)
    for name, data in (("run", run), ("attempt", attempt), ("workflow", workflow),
                       ("pr", pr), ("head", head), ("merge", merge), ("artifact", artifact),
                       ("jobs", jobs)):
        write_json(evidence / f"upstream-{name}.json", data)
    require(shutil.disk_usage(output).free > artifact["size_in_bytes"] + 1024**3,
            "Insufficient disk space for artifact download")
    zipped = output / "artifact.zip"
    print(f"Verified upstream run {values['run_id']}, attempt {values['run_attempt']}; "
          f"downloading artifact {values['artifact_id']}", flush=True)
    with zipped.open("xb") as destination:
        result = subprocess.run(["gh", "api", f"repos/{UPSTREAM}/actions/artifacts/"
                                 f"{values['artifact_id']}/zip"], stdout=destination)
    require(result.returncode == 0, "Artifact download failed; upstream Actions read access is required")
    archive = verify_zip(zipped, values["artifact_sha256"])
    reference = f"oci-archive:{archive}"
    config = json.loads(command(["skopeo", "inspect", "--config", reference]))
    manifest = json.loads(command(["skopeo", "inspect", "--raw", reference]))
    validate_oci(values, config, manifest)
    digest = command(["skopeo", "inspect", "--format", "{{.Digest}}", reference]).decode().strip()
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "Invalid OCI manifest digest")
    # Detect a newer attempt or source update that arrived during the download.
    validate_metadata(values, api(f"actions/runs/{values['run_id']}"), attempt, workflow,
                      api("pulls/737"), head, merge, artifact, jobs)
    tag = f"pr737-build-{values['run_id']}-{values['run_attempt']}-{values['head_sha'][:7]}"
    provenance = {**values, "upstream_repository": UPSTREAM, "image_repository": IMAGE,
                  "image_tag": tag, "image": f"{IMAGE}@{digest}", "manifest_digest": digest,
                  "oci_archive": str(archive), "source_tree_verified": True,
                  "upstream_run_conclusion": "success", "published": False,
                  "publisher_commit": os.environ.get("GITHUB_SHA"),
                  "publisher_run": os.environ.get("GITHUB_RUN_ID")}
    write_json(evidence / "image-config.json", config)
    write_json(evidence / "image-manifest.json", manifest)
    write_json(evidence / "publication.json", provenance)
    print(f"Verified OCI image {digest}; ready to publish unique tag {tag}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        sys.exit(1)
