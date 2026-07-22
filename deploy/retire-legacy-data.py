#!/usr/bin/env python3
"""Retire exact legacy Sub2API data directories after a forward-only cutover.

The default check is offline. Both the evidence-recording stage and destructive
retirement stage require an explicit ``--apply`` from a private root terminal.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass


REPO_DIR = pathlib.Path(__file__).resolve().parent.parent
TARGET_ROOT = pathlib.Path("/mnt/data/sub2api-gate")
STATE_ROOT = pathlib.Path("/run/sub2api-gate")
RECORD_PATH = STATE_ROOT / "legacy-data-retirement.json"
LOCK_PATH = STATE_ROOT / "legacy-data-retirement.lock"
ACTIVE_UPSTREAM = pathlib.Path(
    "/etc/nginx/snippets/sub2api-upstream-active.conf"
)
TRAFFIC_CANARY = REPO_DIR / "deploy" / "traffic-canary.py"
LOG_CLEANUP = REPO_DIR / "deploy" / "cleanup-conversation-logs.sh"
RELEASE_GUARD = REPO_DIR / "deploy" / "require-clean-worktree.sh"
DOCKER_SOCKET = pathlib.Path("/var/run/docker.sock")
DOCKER = "/usr/bin/docker"
FINDMNT = "/usr/bin/findmnt"
FSTRIM = "/usr/sbin/fstrim"
FORWARD_ONLY_PHRASE = "RETIRE LEGACY DATA FORWARD ONLY"
RECORD_VERSION = 1
MAX_RECORD_BYTES = 64 * 1024

CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
PG_ID_RE = re.compile(r"^[0-9]{10,24}$")
REDIS_ID_RE = re.compile(r"^[0-9a-f]{40}$")
DAEMON_ID_RE = re.compile(r"^[A-Za-z0-9_.:+/=-]{8,128}$")
MAJ_MIN_RE = re.compile(r"^[0-9]{1,10}:[0-9]{1,10}$")
DEVICE_RE = re.compile(
    r"^/dev/[A-Za-z0-9_.:+@=/-]+(?:\[[A-Za-z0-9_.:+@=/-]+\])?$"
)
ALLOWED_FILESYSTEMS = frozenset({"ext4", "xfs", "btrfs", "f2fs"})
COMPONENT_DESTINATIONS = {
    "app": "/app/data",
    "postgres": "/var/lib/postgresql/data",
    "redis": "/data",
}
DELETE_ORDER = ("postgres", "redis", "app")
PROTECTED_EXACT_PATHS = frozenset(
    {
        pathlib.Path("/"),
        pathlib.Path("/boot"),
        pathlib.Path("/dev"),
        pathlib.Path("/etc"),
        pathlib.Path("/home"),
        pathlib.Path("/mnt"),
        pathlib.Path("/mnt/data"),
        pathlib.Path("/opt"),
        pathlib.Path("/proc"),
        pathlib.Path("/run"),
        pathlib.Path("/srv"),
        pathlib.Path("/sys"),
        pathlib.Path("/tmp"),
        pathlib.Path("/usr"),
        pathlib.Path("/var"),
        pathlib.Path("/var/lib"),
        pathlib.Path("/var/log"),
    }
)
PROTECTED_TREES = (
    pathlib.Path("/boot"),
    pathlib.Path("/dev"),
    pathlib.Path("/etc"),
    pathlib.Path("/proc"),
    pathlib.Path("/run"),
    pathlib.Path("/sys"),
    pathlib.Path("/usr"),
)


class RetirementError(RuntimeError):
    pass


class UsageError(RetirementError):
    pass


@dataclass(frozen=True)
class LegacyPaths:
    app: pathlib.Path
    postgres: pathlib.Path
    redis: pathlib.Path
    nginx_logs: pathlib.Path

    def data_items(self):
        return (
            ("app", self.app),
            ("postgres", self.postgres),
            ("redis", self.redis),
        )


@dataclass(frozen=True)
class LegacyNames:
    app: str
    postgres: str
    redis: str

    def items(self):
        return (
            ("app", self.app),
            ("postgres", self.postgres),
            ("redis", self.redis),
        )


@dataclass(frozen=True)
class PathPolicy:
    target_root: pathlib.Path = TARGET_ROOT
    repository_root: pathlib.Path = REPO_DIR
    test_root: pathlib.Path | None = None


def run_command(
    command,
    *,
    input_bytes=None,
    timeout=30,
    allow_failure=False,
    environment=None,
):
    child_environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "DOCKER_HOST": "unix:///var/run/docker.sock",
    }
    if environment is not None:
        for key in (
            "SUB2API_DEPLOY_ROOT",
            "SUB2API_CLEANUP_ALLOWED_DEPLOY_ROOTS",
            "SUB2API_DEPLOY_DATA_DIR",
            "SUB2API_NGINX_LOG_DIR",
        ):
            if key in environment:
                child_environment[key] = environment[key]
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            env=child_environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RetirementError("required local command failed") from error
    if result.returncode and not allow_failure:
        raise RetirementError("required local command returned a failure")
    return result


def decoded_stdout(result):
    try:
        return result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise RetirementError("local command returned invalid text") from error


def utc_timestamp():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def is_related(first, second):
    return first == second or first.is_relative_to(second) or second.is_relative_to(first)


def validate_path_shape(path, label, policy):
    path_text = str(path)
    if (
        not path.is_absolute()
        or path_text.startswith("//")
        or any(part in {".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in path_text)
    ):
        raise UsageError(f"{label} must be an explicit normalized absolute path")
    normalized = pathlib.Path(os.path.normpath(str(path)))
    if normalized != path:
        raise UsageError(f"{label} must be an explicit normalized absolute path")
    if path in PROTECTED_EXACT_PATHS or len(path.parts) < 4:
        raise UsageError(f"{label} is too broad for retirement")
    if any(path == root or path.is_relative_to(root) for root in PROTECTED_TREES):
        raise UsageError(f"{label} is below a protected system tree")
    if is_related(path, policy.target_root):
        raise UsageError(f"{label} overlaps the sanitized target data root")
    if is_related(path, policy.repository_root):
        raise UsageError(f"{label} overlaps the repository")
    if policy.test_root is not None:
        if not path.is_relative_to(policy.test_root) or path == policy.test_root:
            raise UsageError(f"{label} must remain below the isolated test root")
    elif path.is_relative_to(pathlib.Path("/tmp")):
        raise UsageError(f"{label} may not use temporary storage in production")
    return path


def validate_path_set(paths, policy):
    data_paths = []
    for component, path in paths.data_items():
        validate_path_shape(path, f"legacy {component} path", policy)
        if policy.test_root is None and path.is_relative_to(pathlib.Path("/var/log")):
            raise UsageError(f"legacy {component} path may not overlap system logs")
        data_paths.append(path)
    validate_path_shape(paths.nginx_logs, "legacy Nginx log path", policy)
    if policy.test_root is None and paths.nginx_logs != pathlib.Path("/var/log/nginx"):
        raise UsageError("legacy Nginx log path must be /var/log/nginx")
    for index, first in enumerate(data_paths):
        for second in data_paths[index + 1 :]:
            if is_related(first, second):
                raise UsageError("legacy data paths must be distinct non-overlapping directories")


def validate_names(names):
    values = []
    for component, name in names.items():
        if not CONTAINER_NAME_RE.fullmatch(name):
            raise UsageError(f"legacy {component} container name is invalid")
        values.append(name)
    if len(set(values)) != len(values):
        raise UsageError("legacy container names must be distinct")


def require_exact_directory(path, label):
    try:
        metadata = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RetirementError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or resolved != path:
        raise RetirementError(f"{label} is not an exact non-symlink directory")
    return metadata


def directory_identity(path, label):
    metadata = require_exact_directory(path, label)
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def require_directory_identity(path, expected, label):
    actual = directory_identity(path, label)
    if actual != expected:
        raise RetirementError(f"{label} no longer matches its recorded identity")


def probe_filesystem(path, *, runner=run_command, allow_mountpoint=False):
    result = runner(
        [FINDMNT, "--json", "--target", str(path), "--output", "TARGET,SOURCE,FSTYPE,MAJ:MIN"],
        timeout=10,
    )
    try:
        payload = json.loads(decoded_stdout(result))
        filesystems = payload["filesystems"]
        item = filesystems[0]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        raise RetirementError("hosting filesystem identity could not be parsed") from error
    if len(filesystems) != 1 or not isinstance(item, dict):
        raise RetirementError("hosting filesystem identity is ambiguous")
    mount_target = item.get("target")
    source = item.get("source")
    filesystem = item.get("fstype")
    major_minor = item.get("maj:min")
    if not all(isinstance(value, str) for value in (mount_target, source, filesystem, major_minor)):
        raise RetirementError("hosting filesystem identity is incomplete")
    target_path = pathlib.Path(mount_target)
    try:
        target_metadata = target_path.stat(follow_symlinks=False)
        resolved_target = target_path.resolve(strict=True)
    except OSError as error:
        raise RetirementError("hosting filesystem mountpoint is unavailable") from error
    if (
        not target_path.is_absolute()
        or target_path.is_symlink()
        or not stat.S_ISDIR(target_metadata.st_mode)
        or resolved_target != target_path
        or not (path == target_path or path.is_relative_to(target_path))
        or filesystem not in ALLOWED_FILESYSTEMS
        or not DEVICE_RE.fullmatch(source)
        or not MAJ_MIN_RE.fullmatch(major_minor)
    ):
        raise RetirementError("hosting filesystem is not approved for discard")
    if path == target_path and not allow_mountpoint:
        raise RetirementError("a legacy data path may not be a filesystem mountpoint")
    return {
        "target": str(target_path),
        "source": source,
        "fstype": filesystem,
        "major_minor": major_minor,
    }


def decode_mount_path(value):
    def replace(match):
        return chr(int(match.group(1), 8))

    decoded = re.sub(r"\\([0-7]{3})", replace, value)
    if "\\" in decoded or "\x00" in decoded:
        raise RetirementError("host mount table contains an invalid path")
    return pathlib.Path(decoded)


def read_mountpoints(path=pathlib.Path("/proc/self/mountinfo")):
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise RetirementError("host mount table could not be read") from error
    mountpoints = []
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            raise RetirementError("host mount table is malformed")
        mountpoint = decode_mount_path(fields[4])
        if not mountpoint.is_absolute():
            raise RetirementError("host mount table contains a relative path")
        mountpoints.append(mountpoint)
    return tuple(mountpoints)


def require_no_nested_mounts(paths, mountpoints):
    for component, path in paths.data_items():
        for mountpoint in mountpoints:
            if mountpoint == path or mountpoint.is_relative_to(path):
                raise RetirementError(
                    f"legacy {component} path contains a mount boundary"
                )


def load_traffic_canary():
    spec = importlib.util.spec_from_file_location("sub2api_traffic_canary", TRAFFIC_CANARY)
    if spec is None or spec.loader is None:
        raise RetirementError("traffic canary gate is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_local_docker_socket():
    try:
        metadata = DOCKER_SOCKET.stat(follow_symlinks=False)
    except OSError as error:
        raise RetirementError("trusted local Docker socket is unavailable") from error
    if (
        DOCKER_SOCKET.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o002
    ):
        raise RetirementError("trusted local Docker socket is unsafe")


def target_runtime_gate(*, runner=run_command):
    traffic = load_traffic_canary()
    try:
        traffic.check_compose_contract()
        return traffic.validate_target_runtime(runner=runner)
    except Exception as error:
        raise RetirementError("sanitized target privacy or health gate failed") from error


def legacy_runtime_gate(names, *, runner=run_command):
    traffic = load_traffic_canary()
    legacy_names = traffic.LegacyNames(names.app, names.postgres, names.redis)
    try:
        return traffic.legacy_identity(legacy_names, runner=runner)
    except Exception as error:
        raise RetirementError("legacy runtime identity could not be verified") from error


def docker_info_value(template, *, runner=run_command):
    result = runner(
        [DOCKER, "--host", "unix:///var/run/docker.sock", "info", "--format", template],
        timeout=10,
    )
    return decoded_stdout(result)


def docker_inspect_value(container, template, *, runner=run_command):
    result = runner(
        [
            DOCKER,
            "--host",
            "unix:///var/run/docker.sock",
            "container",
            "inspect",
            "--format",
            template,
            container,
        ],
        timeout=10,
    )
    return decoded_stdout(result)


def docker_daemon_identity(*, runner=run_command):
    value = docker_info_value("{{.ID}}", runner=runner)
    if not DAEMON_ID_RE.fullmatch(value):
        raise RetirementError("Docker daemon returned an invalid identity")
    return value


def inspect_legacy_containers(paths, names, *, runner=run_command):
    snapshots = {}
    for component, name in names.items():
        identity = docker_inspect_value(
            name,
            "{{.Name}}|{{.Id}}|{{.State.Running}}",
            runner=runner,
        )
        inspected_name, separator, remainder = identity.partition("|")
        container_id, second_separator, running = remainder.partition("|")
        if (
            not separator
            or not second_separator
            or inspected_name != f"/{name}"
            or not CONTAINER_ID_RE.fullmatch(container_id)
            or running != "true"
        ):
            raise RetirementError("legacy container identity or running state is invalid")
        raw_mounts = docker_inspect_value(name, "{{json .Mounts}}", runner=runner)
        try:
            mounts = json.loads(raw_mounts)
        except json.JSONDecodeError as error:
            raise RetirementError("legacy container mount metadata is invalid") from error
        expected_source = str(dict(paths.data_items())[component])
        expected_destination = COMPONENT_DESTINATIONS[component]
        matches = [
            item
            for item in mounts
            if isinstance(item, dict)
            and item.get("Type") == "bind"
            and item.get("Source") == expected_source
            and item.get("Destination") == expected_destination
        ] if isinstance(mounts, list) else []
        if len(matches) != 1:
            raise RetirementError(
                f"legacy {component} path is not the recorded container bind"
            )
        snapshots[component] = {"name": name, "id": container_id}
    return snapshots


def require_legacy_containers_removed(record, *, runner=run_command):
    current_daemon = docker_daemon_identity(runner=runner)
    if current_daemon != record["docker_daemon_id"]:
        raise RetirementError("local Docker daemon does not match recorded evidence")
    result = runner(
        [
            DOCKER,
            "--host",
            "unix:///var/run/docker.sock",
            "container",
            "list",
            "--all",
            "--no-trunc",
            "--format",
            "{{.ID}}|{{.Names}}",
        ],
        timeout=10,
    )
    present_ids = set()
    present_names = set()
    for line in decoded_stdout(result).splitlines():
        container_id, separator, name = line.partition("|")
        if (
            not separator
            or not CONTAINER_ID_RE.fullmatch(container_id)
            or not CONTAINER_NAME_RE.fullmatch(name)
        ):
            raise RetirementError("Docker returned invalid container inventory")
        present_ids.add(container_id)
        present_names.add(name)
    for component in DELETE_ORDER:
        evidence = record["legacy"][component]["container"]
        if evidence["id"] in present_ids or evidence["name"] in present_names:
            raise RetirementError("a recorded legacy container still exists")


def require_upstream_active(expected_port, path=ACTIVE_UPSTREAM):
    try:
        metadata = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RetirementError("active Nginx upstream could not be verified") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or resolved != path
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or metadata.st_size > 64
    ):
        raise RetirementError("Nginx is not pinned to the reviewed upstream stage")
    try:
        content = path.read_bytes()
    except OSError as error:
        raise RetirementError("active Nginx upstream could not be read") from error
    if content != f"server 127.0.0.1:{expected_port};\n".encode("ascii"):
        raise RetirementError("Nginx is not pinned to the reviewed upstream stage")


def require_stable_upstream_active():
    require_upstream_active(8080)


def require_canary_upstream_active():
    require_upstream_active(8081)


def cleanup_environment(paths):
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "SUB2API_DEPLOY_ROOT": str(paths.app.parent),
        "SUB2API_CLEANUP_ALLOWED_DEPLOY_ROOTS": str(paths.app.parent),
        "SUB2API_DEPLOY_DATA_DIR": str(paths.app),
        "SUB2API_NGINX_LOG_DIR": str(paths.nginx_logs),
    }
    return environment


def require_historical_logs_clean(paths, names, *, runner=run_command):
    runner(
        [str(LOG_CLEANUP), "verify", "--legacy-container", names.app],
        timeout=30,
        environment=cleanup_environment(paths),
    )


def nginx_log_residue_exists(path):
    require_exact_directory(path, "legacy Nginx log directory")
    patterns = (
        "sub2api-response.log",
        "sub2api-capture.log",
        "response-preview",
    )
    try:
        for entry in path.rglob("*"):
            if (entry.is_file() or entry.is_symlink()) and any(
                pattern in entry.name for pattern in patterns
            ):
                return True
    except OSError as error:
        raise RetirementError("legacy Nginx logs could not be inspected") from error
    return False


def expected_state_gid(expected_uid):
    return 0 if expected_uid == 0 else os.getgid()


def require_state_parent(record_path, expected_uid):
    parent = record_path.parent
    metadata = require_exact_directory(parent, "retirement evidence directory")
    if (
        metadata.st_uid != expected_uid
        or metadata.st_gid != expected_state_gid(expected_uid)
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RetirementError("retirement evidence directory permissions are unsafe")


def write_record(record_path, record, *, expected_uid):
    require_state_parent(record_path, expected_uid)
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(encoded) > MAX_RECORD_BYTES:
        raise RetirementError("retirement evidence record is too large")
    temporary = record_path.parent / f".{record_path.name}.{os.getpid()}.tmp"
    descriptor = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        created = os.fstat(descriptor)
        expected_gid = expected_state_gid(expected_uid)
        if (created.st_uid, created.st_gid) != (expected_uid, expected_gid):
            os.fchown(descriptor, expected_uid, expected_gid)
        remaining = memoryview(encoded)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short retirement evidence write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, record_path)
        directory_descriptor = os.open(
            record_path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise RetirementError("retirement evidence record could not be committed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_record(record_path, *, expected_uid):
    require_state_parent(record_path, expected_uid)
    descriptor = None
    try:
        descriptor = os.open(record_path, os.O_RDONLY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        path_metadata = record_path.stat(follow_symlinks=False)
    except OSError as error:
        raise RetirementError("retirement evidence record is unavailable") from error
    try:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_state_gid(expected_uid)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 0 < metadata.st_size <= MAX_RECORD_BYTES
        ):
            raise RetirementError("retirement evidence record is unsafe")
        chunks = []
        remaining = MAX_RECORD_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size:
            raise RetirementError("retirement evidence record changed while it was read")
        record = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RetirementError("retirement evidence record is invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    validate_record(record)
    return record


def validate_identity_map(value, *, legacy=False):
    if not isinstance(value, dict) or set(value) != {"app", "postgres", "redis"}:
        raise RetirementError("retirement evidence identity map is invalid")
    if not CONTAINER_ID_RE.fullmatch(str(value["app"])):
        raise RetirementError("retirement evidence app identity is invalid")
    if not PG_ID_RE.fullmatch(str(value["postgres"])):
        raise RetirementError("retirement evidence PostgreSQL identity is invalid")
    if not REDIS_ID_RE.fullmatch(str(value["redis"])):
        raise RetirementError("retirement evidence Redis identity is invalid")


def validate_record(record):
    expected_keys = {
        "version",
        "status",
        "created_at",
        "docker_daemon_id",
        "nginx_logs",
        "legacy",
        "legacy_runtime_identity",
        "retired_components",
        "trimmed_filesystems",
        "cleanup_verified_at",
        "completed_at",
    }
    if not isinstance(record, dict) or set(record) != expected_keys:
        raise RetirementError("retirement evidence schema is invalid")
    if record["version"] != RECORD_VERSION or record["status"] not in {
        "recorded",
        "retiring",
        "complete",
    }:
        raise RetirementError("retirement evidence version or state is invalid")
    if not isinstance(record["created_at"], str) or not record["created_at"]:
        raise RetirementError("retirement evidence timestamp is invalid")
    if not DAEMON_ID_RE.fullmatch(str(record["docker_daemon_id"])):
        raise RetirementError("retirement evidence daemon identity is invalid")
    if not isinstance(record["nginx_logs"], str) or not pathlib.Path(
        record["nginx_logs"]
    ).is_absolute():
        raise RetirementError("retirement evidence Nginx log path is invalid")
    if not isinstance(record["legacy"], dict) or set(record["legacy"]) != set(DELETE_ORDER):
        raise RetirementError("retirement evidence legacy map is invalid")
    for component in DELETE_ORDER:
        value = record["legacy"][component]
        if not isinstance(value, dict) or set(value) != {
            "path",
            "container",
            "directory",
            "filesystem",
        }:
            raise RetirementError("retirement evidence component is invalid")
        container = value["container"]
        if (
            not isinstance(container, dict)
            or set(container) != {"name", "id"}
            or not CONTAINER_NAME_RE.fullmatch(str(container["name"]))
            or not CONTAINER_ID_RE.fullmatch(str(container["id"]))
        ):
            raise RetirementError("retirement evidence container is invalid")
        directory = value["directory"]
        if (
            not isinstance(directory, dict)
            or set(directory) != {"device", "inode", "uid", "gid", "mode"}
            or any(not isinstance(item, int) or item < 0 for item in directory.values())
        ):
            raise RetirementError("retirement evidence directory identity is invalid")
        filesystem = value["filesystem"]
        if (
            not isinstance(filesystem, dict)
            or set(filesystem) != {"target", "source", "fstype", "major_minor"}
            or filesystem["fstype"] not in ALLOWED_FILESYSTEMS
            or not DEVICE_RE.fullmatch(str(filesystem["source"]))
            or not MAJ_MIN_RE.fullmatch(str(filesystem["major_minor"]))
            or not pathlib.Path(str(filesystem["target"])).is_absolute()
        ):
            raise RetirementError("retirement evidence filesystem identity is invalid")
    validate_identity_map(record["legacy_runtime_identity"], legacy=True)
    retired = record["retired_components"]
    if (
        not isinstance(retired, list)
        or len(retired) != len(set(retired))
        or not set(retired) <= set(DELETE_ORDER)
    ):
        raise RetirementError("retirement evidence progress is invalid")
    trimmed = record["trimmed_filesystems"]
    expected_filesystems = {
        filesystem_key(record["legacy"][component]["filesystem"])
        for component in DELETE_ORDER
    }
    if (
        not isinstance(trimmed, list)
        or len(trimmed) != len(set(trimmed))
        or any(not isinstance(item, str) for item in trimmed)
        or not set(trimmed) <= expected_filesystems
    ):
        raise RetirementError("retirement evidence trim progress is invalid")
    for field in ("cleanup_verified_at", "completed_at"):
        if record[field] is not None and not isinstance(record[field], str):
            raise RetirementError("retirement evidence completion timestamp is invalid")
    if record["status"] in {"retiring", "complete"} and record["cleanup_verified_at"] is None:
        raise RetirementError("retirement evidence cleanup state is invalid")
    if record["status"] == "complete" and (
        set(retired) != set(DELETE_ORDER)
        or set(trimmed) != expected_filesystems
        or record["completed_at"] is None
    ):
        raise RetirementError("retirement evidence completion state is invalid")


def filesystem_key(filesystem):
    return json.dumps(
        [filesystem[field] for field in ("major_minor", "source", "fstype", "target")],
        separators=(",", ":"),
    )


def record_matches_arguments(record, paths, names):
    if record["nginx_logs"] != str(paths.nginx_logs):
        raise RetirementError("explicit Nginx log path does not match recorded evidence")
    for component, path in paths.data_items():
        evidence = record["legacy"][component]
        if evidence["path"] != str(path):
            raise RetirementError("explicit legacy path does not match recorded evidence")
    for component, name in names.items():
        if record["legacy"][component]["container"]["name"] != name:
            raise RetirementError("explicit legacy container does not match recorded evidence")


def verify_recorded_identity(
    paths,
    names,
    *,
    record_path=RECORD_PATH,
    expected_uid=0,
    policy=PathPolicy(),
    runner=run_command,
    legacy_gate=legacy_runtime_gate,
    filesystem_probe=probe_filesystem,
    mountpoints_reader=read_mountpoints,
    stable_gate=require_stable_upstream_active,
    container_probe=inspect_legacy_containers,
    daemon_probe=docker_daemon_identity,
):
    validate_path_set(paths, policy)
    validate_names(names)
    record = load_record(record_path, expected_uid=expected_uid)
    record_matches_arguments(record, paths, names)
    if record["status"] != "recorded" or record["retired_components"]:
        raise RetirementError("legacy identity record is no longer pre-maintenance evidence")
    stable_gate()
    current_runtime = legacy_gate(names, runner=runner)
    validate_identity_map(current_runtime, legacy=True)
    if current_runtime != record["legacy_runtime_identity"]:
        raise RetirementError("legacy runtime identity changed after recording")
    if daemon_probe(runner=runner) != record["docker_daemon_id"]:
        raise RetirementError("local Docker daemon does not match recorded evidence")
    snapshots = container_probe(paths, names, runner=runner)
    for component, path in paths.data_items():
        evidence = record["legacy"][component]
        if snapshots[component] != evidence["container"]:
            raise RetirementError("legacy container identity changed after recording")
        require_directory_identity(
            path,
            evidence["directory"],
            f"legacy {component} directory",
        )
        if filesystem_probe(path, runner=runner) != evidence["filesystem"]:
            raise RetirementError("legacy directory hosting filesystem changed")
    require_exact_directory(paths.nginx_logs, "legacy Nginx log directory")
    require_no_nested_mounts(paths, mountpoints_reader())
    return record


def acquire_lock(lock_path, *, expected_uid):
    require_state_parent(lock_path, expected_uid)
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        metadata = os.fstat(descriptor)
        expected_gid = expected_state_gid(expected_uid)
        if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
            os.fchown(descriptor, expected_uid, expected_gid)
            metadata = os.fstat(descriptor)
        path_metadata = lock_path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (path_metadata.st_dev, path_metadata.st_ino)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_state_gid(expected_uid)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise RetirementError("retirement operation lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except (OSError, BlockingIOError) as error:
        raise RetirementError("another legacy retirement operation is active") from error


def create_record(
    paths,
    names,
    *,
    record_path=RECORD_PATH,
    expected_uid=0,
    policy=PathPolicy(),
    runner=run_command,
    legacy_gate=legacy_runtime_gate,
    filesystem_probe=probe_filesystem,
    mountpoints_reader=read_mountpoints,
    stable_gate=require_stable_upstream_active,
    container_probe=inspect_legacy_containers,
    daemon_probe=docker_daemon_identity,
):
    validate_path_set(paths, policy)
    validate_names(names)
    if record_path.exists() or record_path.is_symlink():
        raise RetirementError("retirement evidence record already exists")
    for component, path in paths.data_items():
        require_exact_directory(path, f"legacy {component} directory")
    require_exact_directory(paths.nginx_logs, "legacy Nginx log directory")
    require_no_nested_mounts(paths, mountpoints_reader())
    # Evidence is captured while legacy is still stable; this stage is target-free.
    stable_gate()
    legacy_runtime = legacy_gate(names, runner=runner)
    validate_identity_map(legacy_runtime, legacy=True)
    snapshots = container_probe(paths, names, runner=runner)
    if snapshots["app"]["id"] != legacy_runtime["app"]:
        raise RetirementError("legacy Sub2API identity changed during recording")
    record = {
        "version": RECORD_VERSION,
        "status": "recorded",
        "created_at": utc_timestamp(),
        "docker_daemon_id": daemon_probe(runner=runner),
        "nginx_logs": str(paths.nginx_logs),
        "legacy": {},
        "legacy_runtime_identity": legacy_runtime,
        "retired_components": [],
        "trimmed_filesystems": [],
        "cleanup_verified_at": None,
        "completed_at": None,
    }
    for component, path in paths.data_items():
        record["legacy"][component] = {
            "path": str(path),
            "container": snapshots[component],
            "directory": directory_identity(path, f"legacy {component} directory"),
            "filesystem": filesystem_probe(path, runner=runner),
        }
    validate_record(record)
    write_record(record_path, record, expected_uid=expected_uid)
    return record


def probe_mountpoint_filesystem(path, *, runner=run_command):
    return probe_filesystem(path, runner=runner, allow_mountpoint=True)


def require_current_filesystem(
    expected,
    *,
    runner=run_command,
    mountpoint_probe=probe_mountpoint_filesystem,
):
    current = mountpoint_probe(pathlib.Path(expected["target"]), runner=runner)
    if current != expected:
        raise RetirementError("hosting filesystem no longer matches recorded evidence")


def delete_exact_directory(path, expected):
    require_directory_identity(path, expected, "legacy data directory")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise RetirementError("this Python runtime lacks symlink-safe directory removal")
    try:
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            child_descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_descriptor,
            )
            try:
                metadata = os.fstat(child_descriptor)
                if {
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                    "mode": stat.S_IMODE(metadata.st_mode),
                } != expected:
                    raise RetirementError("legacy data directory changed before removal")
            finally:
                os.close(child_descriptor)
            shutil.rmtree(path.name, dir_fd=parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except (OSError, shutil.Error) as error:
        raise RetirementError("exact legacy data directory removal failed") from error
    if os.path.lexists(path):
        raise RetirementError("legacy data directory still exists after removal")


def trim_filesystem(filesystem, *, runner=run_command):
    runner(
        [FSTRIM, "--quiet-unsupported", "--", filesystem["target"]],
        timeout=300,
    )


def require_forward_only_confirmation(stdin, stderr):
    if not stdin.isatty() or not stderr.isatty():
        raise RetirementError("legacy retirement requires a private interactive terminal")
    print(
        "Legacy physical data will be destroyed and rollback becomes forward-only.\n"
        "This removal plus fstrim is not a guarantee of forensic-grade erasure.\n"
        f"Type exactly: {FORWARD_ONLY_PHRASE}",
        file=stderr,
    )
    if stdin.readline().rstrip("\r\n") != FORWARD_ONLY_PHRASE:
        raise RetirementError("forward-only confirmation did not match")


def retire_recorded_data(
    paths,
    names,
    *,
    record_path=RECORD_PATH,
    expected_uid=0,
    policy=PathPolicy(),
    runner=run_command,
    target_gate=target_runtime_gate,
    filesystem_probe=probe_filesystem,
    mountpoint_probe=probe_mountpoint_filesystem,
    mountpoints_reader=read_mountpoints,
    nginx_gate=require_canary_upstream_active,
    container_gate=require_legacy_containers_removed,
    cleanup_gate=require_historical_logs_clean,
    delete_directory=delete_exact_directory,
    trimmer=trim_filesystem,
    stdin=sys.stdin,
    stderr=sys.stderr,
):
    validate_path_set(paths, policy)
    validate_names(names)
    record = load_record(record_path, expected_uid=expected_uid)
    record_matches_arguments(record, paths, names)
    if record["status"] == "complete":
        return record

    # Finish every live-system and path gate before asking for destructive consent.
    nginx_gate()
    container_gate(record, runner=runner)
    current_target = target_gate(runner=runner)
    validate_identity_map(current_target)
    for component in DELETE_ORDER:
        if record["legacy_runtime_identity"][component] == current_target[component]:
            raise RetirementError("migrated target aliases a legacy runtime identity")

    retired = set(record["retired_components"])
    if "app" not in retired:
        cleanup_gate(paths, names, runner=runner)
        record["cleanup_verified_at"] = utc_timestamp()
        write_record(record_path, record, expected_uid=expected_uid)
    else:
        if record["cleanup_verified_at"] is None or nginx_log_residue_exists(paths.nginx_logs):
            raise RetirementError("historical log cleanup evidence is incomplete")

    mountpoints = mountpoints_reader()
    require_no_nested_mounts(
        LegacyPaths(
            app=(
                paths.app
                if "app" not in retired
                else paths.app.parent / ".retired-app-placeholder"
            ),
            postgres=(
                paths.postgres
                if "postgres" not in retired
                else paths.postgres.parent / ".retired-postgres-placeholder"
            ),
            redis=(
                paths.redis
                if "redis" not in retired
                else paths.redis.parent / ".retired-redis-placeholder"
            ),
            nginx_logs=paths.nginx_logs,
        ),
        mountpoints,
    )
    for component, path in paths.data_items():
        evidence = record["legacy"][component]
        if component in retired:
            if os.path.lexists(path):
                raise RetirementError("a recorded retired path was recreated")
        else:
            require_directory_identity(
                path,
                evidence["directory"],
                f"legacy {component} directory",
            )
            current_filesystem = filesystem_probe(path, runner=runner)
            if current_filesystem != evidence["filesystem"]:
                raise RetirementError("legacy directory hosting filesystem changed")

    filesystems = {}
    for component in DELETE_ORDER:
        filesystem = record["legacy"][component]["filesystem"]
        filesystems.setdefault(filesystem_key(filesystem), filesystem)
    for filesystem in filesystems.values():
        require_current_filesystem(
            filesystem,
            runner=runner,
            mountpoint_probe=mountpoint_probe,
        )

    require_forward_only_confirmation(stdin, stderr)
    record["status"] = "retiring"
    write_record(record_path, record, expected_uid=expected_uid)

    for component in DELETE_ORDER:
        if component in retired:
            continue
        evidence = record["legacy"][component]
        delete_directory(pathlib.Path(evidence["path"]), evidence["directory"])
        retired.add(component)
        record["retired_components"] = [name for name in DELETE_ORDER if name in retired]
        write_record(record_path, record, expected_uid=expected_uid)

    trimmed = set(record["trimmed_filesystems"])
    for key, filesystem in filesystems.items():
        if key in trimmed:
            continue
        require_current_filesystem(
            filesystem,
            runner=runner,
            mountpoint_probe=mountpoint_probe,
        )
        trimmer(filesystem, runner=runner)
        trimmed.add(key)
        record["trimmed_filesystems"] = sorted(trimmed)
        write_record(record_path, record, expected_uid=expected_uid)

    record["status"] = "complete"
    record["completed_at"] = utc_timestamp()
    write_record(record_path, record, expected_uid=expected_uid)
    return record


def parse_arguments(argv):
    arguments = list(argv)
    mode = arguments.pop(0) if arguments else "check"
    if mode not in {"check", "verify-record", "--apply"}:
        raise UsageError(
            "usage: retire-legacy-data.py [check|verify-record|--apply --stage record|retire ...]"
        )
    if mode == "check":
        if arguments:
            raise UsageError("check mode does not accept runtime paths or identities")
        return mode, None, None, None, False, RECORD_PATH
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--stage", choices=("record", "retire"))
    parser.add_argument("--record-file", type=pathlib.Path, default=RECORD_PATH)
    parser.add_argument("--legacy-app-path", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-postgres-path", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-redis-path", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-nginx-log-path", type=pathlib.Path, required=True)
    parser.add_argument("--legacy-sub2api-container", required=True)
    parser.add_argument("--legacy-postgres-container", required=True)
    parser.add_argument("--legacy-redis-container", required=True)
    parser.add_argument("--confirm-forward-only", action="store_true")
    try:
        options = parser.parse_args(arguments)
    except SystemExit as error:
        raise UsageError("invalid legacy retirement arguments") from error
    if options.record_file != RECORD_PATH:
        raise UsageError("production retirement evidence must use the fixed record path")
    if mode == "verify-record" and options.stage is not None:
        raise UsageError("verify-record does not accept an apply stage")
    if mode == "verify-record" and options.confirm_forward_only:
        raise UsageError("verify-record does not accept forward-only confirmation")
    if mode == "--apply" and options.stage is None:
        raise UsageError("--apply requires --stage record or retire")
    if options.stage == "record" and options.confirm_forward_only:
        raise UsageError("forward-only confirmation is valid only for retire stage")
    if options.stage == "retire" and not options.confirm_forward_only:
        raise UsageError("retire stage requires --confirm-forward-only")
    paths = LegacyPaths(
        app=options.legacy_app_path,
        postgres=options.legacy_postgres_path,
        redis=options.legacy_redis_path,
        nginx_logs=options.legacy_nginx_log_path,
    )
    names = LegacyNames(
        app=options.legacy_sub2api_container,
        postgres=options.legacy_postgres_container,
        redis=options.legacy_redis_container,
    )
    validate_path_set(paths, PathPolicy())
    validate_names(names)
    return mode, options.stage, paths, names, options.confirm_forward_only, options.record_file


def check_contract():
    for path in (TRAFFIC_CANARY, LOG_CLEANUP, RELEASE_GUARD):
        if not path.is_file() or path.is_symlink():
            raise RetirementError("a required retirement gate is unavailable")
    if TARGET_ROOT != pathlib.Path("/mnt/data/sub2api-gate"):
        raise RetirementError("sanitized target root contract changed")


def main(
    argv=None,
    *,
    runner=run_command,
    stdin=None,
    stderr=None,
    stdout=None,
):
    argv = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin if stdin is None else stdin
    stderr = sys.stderr if stderr is None else stderr
    stdout = sys.stdout if stdout is None else stdout
    lock_descriptor = None
    try:
        mode, stage, paths, names, _confirmed, record_path = parse_arguments(argv)
        check_contract()
        if mode == "check":
            print(
                "legacy data retirement contract check passed; no path was resolved, "
                "no Docker or health gate ran, and no file was changed. fstrim can only "
                "request discard and does not guarantee forensic-grade erasure",
                file=stdout,
            )
            return 0
        if mode == "verify-record":
            if os.geteuid() != 0:
                raise RetirementError("legacy identity verification must run as root")
            require_local_docker_socket()
            verify_recorded_identity(
                paths,
                names,
                record_path=record_path,
                runner=runner,
            )
            print(
                "pre-maintenance legacy container, runtime, bind, path, and filesystem "
                "identities match the root-only record; no file was changed",
                file=stdout,
            )
            return 0
        if os.geteuid() != 0:
            raise RetirementError("legacy data retirement must run as root")
        if not stdin.isatty() or not stderr.isatty():
            raise RetirementError("legacy data retirement requires a private interactive terminal")
        require_local_docker_socket()
        lock_descriptor = acquire_lock(LOCK_PATH, expected_uid=0)
        runner([str(RELEASE_GUARD), "check"], timeout=15)
        if stage == "record":
            create_record(paths, names, record_path=record_path, runner=runner)
            print(
                "legacy runtime, path, and filesystem identities were recorded; "
                "no legacy data was deleted",
                file=stdout,
            )
        else:
            result = retire_recorded_data(
                paths,
                names,
                record_path=record_path,
                runner=runner,
                stdin=stdin,
                stderr=stderr,
            )
            if result["status"] == "complete":
                print(
                    "exact legacy app, PostgreSQL, and Redis directories are retired; "
                    "filesystem discard was requested where supported. This is not a "
                    "guarantee of forensic-grade erasure",
                    file=stdout,
                )
        return 0
    except UsageError as error:
        print(str(error), file=stderr)
        return 2
    except RetirementError as error:
        print(str(error), file=stderr)
        return 1
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
