#!/usr/bin/python3 -I
"""Harden the fixed legacy Sub2API Redis service without exposing passwords.

This is a one-time, deliberately narrow controller for the legacy source stack
that still serves loopback 8080.  It does not participate in the sanitized
data migration.  The only mutable source is the exact legacy Compose project;
all Docker commands are pinned to the local Unix socket and an empty root-only
Docker config directory.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import getpass
import hashlib
import hmac
import http.client
import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import time
from typing import Callable


REPO_DIR = pathlib.Path(__file__).resolve().parents[1]
TRUSTED_RELEASE_ROOT = pathlib.Path("/opt/sub2api-gate-release")
RELEASE_GUARD = TRUSTED_RELEASE_ROOT / "deploy" / "require-clean-worktree.sh"
LEGACY_ROOT = pathlib.Path("/home/ubuntu/sub2api-deploy")
LEGACY_COMPOSE_FILE = LEGACY_ROOT / "docker-compose.local.yml"
LEGACY_ENV_FILE = LEGACY_ROOT / ".env"
LEGACY_REDIS_DATA = LEGACY_ROOT / "redis_data"
PRIVATE_ROOT = pathlib.Path("/mnt/data/sub2api-gate/private")
STATE_DIR = PRIVATE_ROOT / "legacy-redis-hardening"
ACL_DIR = PRIVATE_ROOT / "legacy-redis"
ACL_FILE = ACL_DIR / "users.acl"
DOCKER_SOCKET = pathlib.Path("/var/run/docker.sock")
DOCKER_CONFIG_DIR = pathlib.Path("/run/sub2api-gate/legacy-redis-docker")

DOCKER_BINARY = pathlib.Path("/usr/bin/docker")
SAFE_PROCESS_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
LEGACY_PROJECT = "sub2api-deploy"
LEGACY_APP_SERVICE = "sub2api"
LEGACY_REDIS_SERVICE = "redis"
LEGACY_APP_CONTAINER = "sub2api"
LEGACY_REDIS_CONTAINER = "sub2api-redis"
LEGACY_APP_PORT = 8080

MAX_COMPOSE_BYTES = 512 * 1024
MAX_ENV_BYTES = 128 * 1024
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 45
STARTUP_TIMEOUT_SECONDS = 90
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
CONTAINER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
ENV_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*\Z")
IMAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:-]{0,255}\Z")
IMAGE_ID_RE = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
SERVICE_RE = re.compile(r"^  ([A-Za-z0-9][A-Za-z0-9_.-]*):[ \t]*(?:#.*)?$")
TOP_LEVEL_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*:[ \t]*(?:#.*)?$")
SCALAR_FIELD_RE = re.compile(r"^ {4}([A-Za-z][A-Za-z0-9_-]*):[ \t]*(.*?)\s*$")

FORBIDDEN_ENV_PREFIXES = ("COMPOSE_", "DOCKER_")
FORBIDDEN_PASSWORD_CHARACTERS = frozenset("'\"\\#$")
RECOVERY_FILES = ("compose.before", "env.before", "state.json")
ACL_CONTENT_RE = re.compile(r"user default reset on #[0-9a-f]{64} resetkeys ~\* resetchannels &\* \+@all -@admin -@dangerous\n\Z")


class LegacyRedisHardeningError(RuntimeError):
    pass


class UsageError(LegacyRedisHardeningError):
    pass


class CommandError(LegacyRedisHardeningError):
    pass


class RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise UsageError("legacy Redis hardening command validation failed")


@dataclasses.dataclass(frozen=True)
class HardeningPaths:
    legacy_root: pathlib.Path
    compose_file: pathlib.Path
    env_file: pathlib.Path
    redis_data: pathlib.Path
    private_root: pathlib.Path
    state_dir: pathlib.Path
    acl_dir: pathlib.Path
    acl_file: pathlib.Path
    docker_socket: pathlib.Path
    docker_config_dir: pathlib.Path


@dataclasses.dataclass(frozen=True)
class FileSnapshot:
    data: bytes
    uid: int
    gid: int
    mode: int


@dataclasses.dataclass(frozen=True)
class DirectorySnapshot:
    uid: int
    gid: int
    mode: int


@dataclasses.dataclass(frozen=True)
class ContainerMetadata:
    identity: str
    name: str
    running: bool
    health: str
    image: str
    image_identity: str
    project: str
    service: str


@dataclasses.dataclass(frozen=True)
class RuntimeSnapshot:
    app: ContainerMetadata
    redis: ContainerMetadata
    app_image_identity: str
    redis_image_identity: str


@dataclasses.dataclass(frozen=True)
class SourceContract:
    redis_image: str
    networks: tuple[str, ...]
    hardened_compose: bytes


@dataclasses.dataclass
class CommandResult:
    returncode: int
    stdout: bytes = b""


def production_paths():
    return HardeningPaths(
        legacy_root=LEGACY_ROOT,
        compose_file=LEGACY_COMPOSE_FILE,
        env_file=LEGACY_ENV_FILE,
        redis_data=LEGACY_REDIS_DATA,
        private_root=PRIVATE_ROOT,
        state_dir=STATE_DIR,
        acl_dir=ACL_DIR,
        acl_file=ACL_FILE,
        docker_socket=DOCKER_SOCKET,
        docker_config_dir=DOCKER_CONFIG_DIR,
    )


def _process_environment(_source=None, *, docker_config_dir=DOCKER_CONFIG_DIR):
    # Docker commands use a fixed executable and never inherit caller selectors.
    return {
        "PATH": SAFE_PROCESS_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "DOCKER_CONFIG": str(docker_config_dir),
    }


def _command_result(result):
    stdout = result.stdout
    if isinstance(stdout, str):
        stdout = stdout.encode("utf-8", errors="strict")
    if not isinstance(stdout, bytes) or len(stdout) > MAX_COMMAND_OUTPUT_BYTES:
        raise CommandError("legacy Redis command returned invalid metadata")
    return CommandResult(result.returncode, stdout)


def run_command(argv, *, timeout, environment, input_data=None, allow_failure=False):
    try:
        result = subprocess.run(
            [str(value) for value in argv],
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CommandError("required local command could not be completed") from error
    command_result = _command_result(result)
    if command_result.returncode and not allow_failure:
        raise CommandError("required local command failed")
    return command_result


def _decoded_stdout(result):
    try:
        value = result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeError as error:
        raise LegacyRedisHardeningError("legacy Redis runtime metadata is invalid") from error
    if len(value.encode("utf-8")) > MAX_COMMAND_OUTPUT_BYTES:
        raise LegacyRedisHardeningError("legacy Redis runtime metadata is invalid")
    return value


def _stat_regular(path, *, maximum_bytes, expected_uid=None, expected_mode=None):
    path = pathlib.Path(path)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise LegacyRedisHardeningError("required private file is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum_bytes
        or (expected_uid is not None and metadata.st_uid != expected_uid)
        or (expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode)
    ):
        raise LegacyRedisHardeningError("required private file has an unsafe identity")
    return metadata


def _require_trusted_docker_binary(path=DOCKER_BINARY, *, expected_uid=0):
    path = pathlib.Path(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LegacyRedisHardeningError("trusted Docker binary is unavailable") from error
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not metadata.st_mode & stat.S_IXUSR
    ):
        raise LegacyRedisHardeningError("trusted Docker binary has an unsafe identity")
    return path


def _require_trusted_directory_chain(path, *, expected_uid, root=pathlib.Path("/")):
    """Require root-controlled, non-writable directories from ``root`` to ``path``."""
    path = pathlib.Path(path)
    root = pathlib.Path(root)
    if not path.is_absolute() or not root.is_absolute():
        raise LegacyRedisHardeningError("trusted legacy source path is unsafe")
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise LegacyRedisHardeningError("trusted legacy source path is unsafe") from error
    current = root
    candidates = [current]
    for component in relative.parts:
        current = current / component
        candidates.append(current)
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except OSError as error:
            raise LegacyRedisHardeningError("trusted legacy source path is unsafe") from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise LegacyRedisHardeningError("trusted legacy source path is unsafe")


def _require_trusted_legacy_source_path(path, *, expected_uid):
    if pathlib.Path(path) != LEGACY_ROOT:
        raise LegacyRedisHardeningError("trusted legacy source path is unsafe")
    _require_trusted_directory_chain(path, expected_uid=expected_uid)


def _require_trusted_release_tree(
    *,
    repo_dir=REPO_DIR,
    trusted_root=TRUSTED_RELEASE_ROOT,
    source_path=None,
    release_guard=RELEASE_GUARD,
    expected_uid=0,
):
    repo_dir = pathlib.Path(repo_dir)
    trusted_root = pathlib.Path(trusted_root)
    release_guard = pathlib.Path(release_guard)
    if repo_dir != trusted_root:
        raise LegacyRedisHardeningError("legacy Redis hardening must run from the trusted release tree")
    expected_source = trusted_root / "deploy" / "harden-legacy-redis.py"
    expected_guard = trusted_root / "deploy" / "require-clean-worktree.sh"
    if release_guard != expected_guard:
        raise LegacyRedisHardeningError("trusted legacy Redis release guard is invalid")
    if source_path is None:
        try:
            source_path = pathlib.Path(__file__).resolve(strict=True)
        except OSError as error:
            raise LegacyRedisHardeningError("trusted legacy Redis hardening source is unavailable") from error
    else:
        source_path = pathlib.Path(source_path)
    if source_path != expected_source:
        raise LegacyRedisHardeningError("legacy Redis hardening source is outside the trusted release tree")
    expected_entries = (
        (trusted_root.parent, True, False),
        (trusted_root, True, False),
        (trusted_root / "deploy", True, False),
        (source_path, False, False),
        (release_guard, False, True),
    )
    for path, expects_directory, requires_executable in expected_entries:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise LegacyRedisHardeningError("trusted release tree is unavailable") from error
        if (
            path.is_symlink()
            or (expects_directory and not stat.S_ISDIR(metadata.st_mode))
            or (not expects_directory and not stat.S_ISREG(metadata.st_mode))
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or (requires_executable and not metadata.st_mode & stat.S_IXUSR)
        ):
            raise LegacyRedisHardeningError("trusted release tree has an unsafe identity")


def _read_regular_file(path, *, maximum_bytes, expected_uid=None, expected_mode=None):
    metadata = _stat_regular(
        path,
        maximum_bytes=maximum_bytes,
        expected_uid=expected_uid,
        expected_mode=expected_mode,
    )
    if not hasattr(os, "O_NOFOLLOW"):
        raise LegacyRedisHardeningError("safe local file access is unavailable")
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
            or opened.st_uid != metadata.st_uid
            or opened.st_gid != metadata.st_gid
            or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(metadata.st_mode)
        ):
            raise LegacyRedisHardeningError("required private file changed while being read")
        chunks = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum_bytes:
            raise LegacyRedisHardeningError("required private file is too large")
        final = os.fstat(descriptor)
        if (
            final.st_dev != opened.st_dev
            or final.st_ino != opened.st_ino
            or final.st_size != opened.st_size
            or final.st_mtime_ns != opened.st_mtime_ns
            or final.st_ctime_ns != opened.st_ctime_ns
        ):
            raise LegacyRedisHardeningError("required private file changed while being read")
        return FileSnapshot(
            data=data,
            uid=opened.st_uid,
            gid=opened.st_gid,
            mode=stat.S_IMODE(opened.st_mode),
        )
    except OSError as error:
        raise LegacyRedisHardeningError("required private file could not be read") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_directory(path, *, expected_uid, expected_mode, create=False):
    path = pathlib.Path(path)
    try:
        if create:
            path.mkdir(mode=expected_mode)
        metadata = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except FileExistsError:
        try:
            metadata = path.stat(follow_symlinks=False)
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise LegacyRedisHardeningError("required private directory is unavailable") from error
    except OSError as error:
        raise LegacyRedisHardeningError("required private directory is unavailable") from error
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != expected_mode
    ):
        raise LegacyRedisHardeningError("required private directory has an unsafe identity")
    return metadata


def _fsync_directory(directory):
    try:
        descriptor = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise LegacyRedisHardeningError("private directory could not be synchronized") from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise LegacyRedisHardeningError("private directory could not be synchronized") from error
    finally:
        os.close(descriptor)


def _atomic_write(
    path,
    payload,
    *,
    mode,
    owner_uid,
    owner_gid=None,
    parent_mode=0o700,
):
    path = pathlib.Path(path)
    owner_gid = owner_uid if owner_gid is None else owner_gid
    parent = path.parent
    _require_directory(parent, expected_uid=owner_uid, expected_mode=parent_mode)
    temporary = parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, mode)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fchown(descriptor, owner_uid, owner_gid)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        _fsync_directory(parent)
    except OSError as error:
        raise LegacyRedisHardeningError("private file could not be written atomically") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
    _stat_regular(path, maximum_bytes=max(len(payload), 1), expected_uid=owner_uid, expected_mode=mode)


def _safe_unlink(path, *, expected_uid, expected_mode, maximum_bytes=MAX_ENV_BYTES):
    path = pathlib.Path(path)
    try:
        _stat_regular(
            path,
            maximum_bytes=maximum_bytes,
            expected_uid=expected_uid,
            expected_mode=expected_mode,
        )
    except LegacyRedisHardeningError:
        if not path.exists() and not path.is_symlink():
            return
        raise
    try:
        path.unlink()
        _fsync_directory(path.parent)
    except OSError as error:
        raise LegacyRedisHardeningError("private recovery file could not be removed") from error


def _decode_text(payload, label):
    if b"\x00" in payload or b"\r" in payload:
        raise LegacyRedisHardeningError(f"{label} uses an unsafe encoding")
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise LegacyRedisHardeningError(f"{label} uses an unsafe encoding") from error


def _strip_simple_quotes(value):
    value = value.strip()
    if len(value) >= 2 and value[0] in {"'", '"'}:
        if value[-1] != value[0] or "\\" in value[1:-1]:
            raise LegacyRedisHardeningError("legacy Compose scalar is ambiguous")
        value = value[1:-1]
    if not value or any(character in value for character in "\r\n\x00"):
        raise LegacyRedisHardeningError("legacy Compose scalar is invalid")
    return value


def _service_blocks(compose_text):
    if len(compose_text.encode("utf-8")) > MAX_COMPOSE_BYTES:
        raise LegacyRedisHardeningError("legacy Compose file is too large")
    if "\r" in compose_text or "\x00" in compose_text:
        raise LegacyRedisHardeningError("legacy Compose file is unsafe")
    if re.search(r"(?m)^(?:include|name):", compose_text) or re.search(
        r"(?m)^ {4}(?:extends|<<):", compose_text
    ):
        raise LegacyRedisHardeningError("legacy Compose file uses an unsupported include or merge")
    lines = compose_text.splitlines(keepends=True)
    services_index = None
    for index, line in enumerate(lines):
        if line.rstrip("\n") == "services:":
            if services_index is not None:
                raise LegacyRedisHardeningError("legacy Compose file has duplicate services sections")
            services_index = index
    if services_index is None:
        raise LegacyRedisHardeningError("legacy Compose services section is missing")
    services_end = len(lines)
    for index in range(services_index + 1, len(lines)):
        current = lines[index].rstrip("\n")
        if TOP_LEVEL_KEY_RE.fullmatch(current):
            services_end = index
            break
    starts = []
    for index in range(services_index + 1, services_end):
        match = SERVICE_RE.fullmatch(lines[index].rstrip("\n"))
        if match:
            starts.append((index, match.group(1)))
    if not starts:
        raise LegacyRedisHardeningError("legacy Compose services section is empty")
    result = {}
    offsets = []
    current_offset = 0
    for line in lines:
        offsets.append(current_offset)
        current_offset += len(line)
    for position, (start, name) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else services_end
        if name in result:
            raise LegacyRedisHardeningError("legacy Compose service is duplicated")
        result[name] = (offsets[start], offsets[end] if end < len(offsets) else len(compose_text), "".join(lines[start:end]))
    return result


def _scalar_values(block, field):
    values = []
    for line in block.splitlines():
        match = SCALAR_FIELD_RE.fullmatch(line)
        if match and match.group(1) == field:
            values.append(_strip_simple_quotes(match.group(2)))
    return values


def _require_scalar(block, field, expected=None):
    values = _scalar_values(block, field)
    if len(values) != 1:
        raise LegacyRedisHardeningError("legacy Compose service contract is invalid")
    value = values[0]
    if expected is not None and value != expected:
        raise LegacyRedisHardeningError("legacy Compose service contract is invalid")
    return value


def _section_lines(block, field):
    lines = block.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if re.fullmatch(rf" {{4}}{re.escape(field)}:[ \t]*", line)
    ]
    if len(starts) > 1:
        raise LegacyRedisHardeningError("legacy Compose service contract is invalid")
    if not starts:
        return None
    start = starts[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith(" "):
            end = index
            break
        if re.fullmatch(r" {4}[A-Za-z][A-Za-z0-9_-]*:[ \t]*.*", line):
            end = index
            break
    return lines[start + 1:end]


def _simple_networks(block):
    values = _section_lines(block, "networks")
    if values is None:
        return ()
    result = []
    for line in values:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r" {6}- ([A-Za-z0-9][A-Za-z0-9_.-]{0,127})", line)
        if not match or match.group(1) in result:
            raise LegacyRedisHardeningError("legacy Compose network contract is invalid")
        result.append(match.group(1))
    if not result:
        raise LegacyRedisHardeningError("legacy Compose network contract is invalid")
    return tuple(result)


def _forbid_unsafe_service_constructs(block):
    forbidden = (
        r"(?m)^ {4}privileged:\s*true\s*$",
        r"(?m)^ {4}(?:network_mode|pid|ipc):\s*['\"]?host",
        r"(?m)^ {4}(?:cap_add|devices|userns_mode|build|extends):",
        r"(?m)^ {4}<<:",
        r"/var/run/docker\.sock",
    )
    if any(re.search(pattern, block) for pattern in forbidden):
        raise LegacyRedisHardeningError("legacy Compose service contract is unsafe")


def _app_redis_environment_is_safe(block):
    host_lines = re.findall(
        r"(?m)^ {6}(?:- )?REDIS_HOST(?:=|:\s*)([^\s#]+)\s*$", block
    )
    password_lines = re.findall(
        r"(?m)^ {6}(?:- )?REDIS_PASSWORD(?:=|:\s*)([^\s#]+)\s*$", block
    )
    if host_lines != ["redis"] or len(password_lines) != 1:
        raise LegacyRedisHardeningError("legacy application Redis environment is invalid")
    if not password_lines[0].startswith("${REDIS_PASSWORD"):
        raise LegacyRedisHardeningError("legacy application Redis environment is invalid")
    scalar_env_file = _scalar_values(block, "env_file")
    if len(scalar_env_file) > 1 or scalar_env_file not in ([], [".env"], ["./.env"]):
        raise LegacyRedisHardeningError("legacy application environment file is unsafe")
    env_file = _section_lines(block, "env_file")
    if env_file is not None:
        permitted = {
            "      - .env",
            "      - ./.env",
            "      - \".env\"",
            "      - \"./.env\"",
        }
        if any(line.strip() and not line.lstrip().startswith("#") and line not in permitted for line in env_file):
            raise LegacyRedisHardeningError("legacy application environment file is unsafe")


def _legacy_redis_volume_is_safe(block):
    volume_lines = _section_lines(block, "volumes")
    if volume_lines is None:
        raise LegacyRedisHardeningError("legacy Redis data volume is missing")
    normalized = [line.strip() for line in volume_lines if line.strip() and not line.lstrip().startswith("#")]
    if normalized != ["- ./redis_data:/data", "- ./redis_data:/data:rw"] and normalized not in (
        ["- ./redis_data:/data"],
        ["- ./redis_data:/data:rw"],
    ):
        raise LegacyRedisHardeningError("legacy Redis data volume contract is invalid")


def validate_acl_content(payload):
    if isinstance(payload, bytes):
        try:
            content = payload.decode("ascii", errors="strict")
        except UnicodeError as error:
            raise LegacyRedisHardeningError("legacy Redis ACL content is invalid") from error
    else:
        content = payload
    if not isinstance(content, str) or not ACL_CONTENT_RE.fullmatch(content):
        raise LegacyRedisHardeningError("legacy Redis ACL content is invalid")
    return content


def render_acl(password):
    validate_password(password, "new Redis password")
    digest = hashlib.sha256(password.encode("ascii")).hexdigest()
    content = (
        "user default reset on "
        f"#{digest} "
        "resetkeys ~* resetchannels &* +@all -@admin -@dangerous\n"
    )
    validate_acl_content(content)

    return content

def _hardened_redis_service(image, networks, *, acl_file):
    network_lines = "".join(f"      - {network}\n" for network in networks)
    networks_block = f"    networks:\n{network_lines}" if networks else ""
    return (
        "  redis:\n"
        f"    image: {image}\n"
        f"    container_name: {LEGACY_REDIS_CONTAINER}\n"
        "    user: \"0:0\"\n"
        "    command:\n"
        "      - redis-server\n"
        "      - --aclfile\n"
        "      - /etc/redis/users.acl\n"
        "      - --appendonly\n"
        "      - \"no\"\n"
        "      - --save\n"
        "      - \"\"\n"
        "      - --dir\n"
        "      - /data\n"
        "      - --dbfilename\n"
        "      - dump.rdb\n"
        "      - --protected-mode\n"
        "      - \"yes\"\n"
        "      - --maxmemory\n"
        "      - 128mb\n"
        "      - --maxmemory-policy\n"
        "      - noeviction\n"
        "    volumes:\n"
        f"      - {acl_file}:/etc/redis/users.acl:ro\n"
        "    tmpfs:\n"
        "      - /data:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=0,gid=0\n"
        "      - /tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777,uid=0,gid=0\n"
        "    read_only: true\n"
        "    cap_drop:\n"
        "      - ALL\n"
        "    security_opt:\n"
        "      - no-new-privileges:true\n"
        "    pids_limit: 128\n"
        "    mem_limit: 256m\n"
        "    ulimits:\n"
        "      core: 0\n"
        "    logging:\n"
        "      driver: \"none\"\n"
        "    healthcheck:\n"
        "      test:\n"
        "        - CMD-SHELL\n"
        "        - redis-cli --no-auth-warning ping 2>&1 | grep -Fq 'NOAUTH Authentication required'\n"
        "      interval: 5s\n"
        "      timeout: 3s\n"
        "      retries: 12\n"
        "      start_period: 5s\n"
        "    restart: unless-stopped\n"
        f"{networks_block}"
    )


def transform_compose(compose_payload, *, acl_file=ACL_FILE):
    compose_text = _decode_text(compose_payload, "legacy Compose file")
    blocks = _service_blocks(compose_text)
    if set((LEGACY_APP_SERVICE, LEGACY_REDIS_SERVICE)) - set(blocks):
        raise LegacyRedisHardeningError("legacy Compose services are incomplete")
    redis_start, redis_end, redis_block = blocks[LEGACY_REDIS_SERVICE]
    _forbid_unsafe_service_constructs(redis_block)
    _forbid_unsafe_service_constructs(blocks[LEGACY_APP_SERVICE][2])
    image = _require_scalar(redis_block, "image")
    if not IMAGE_RE.fullmatch(image):
        raise LegacyRedisHardeningError("legacy Redis image is invalid")
    _require_scalar(redis_block, "container_name", LEGACY_REDIS_CONTAINER)
    _require_scalar(blocks[LEGACY_APP_SERVICE][2], "container_name", LEGACY_APP_CONTAINER)
    if "sh -c" not in redis_block or "--requirepass" not in redis_block:
        raise LegacyRedisHardeningError("legacy Redis command is not the reviewed shell contract")
    if '${REDIS_PASSWORD:+--requirepass "$REDIS_PASSWORD"}' not in redis_block:
        raise LegacyRedisHardeningError("legacy Redis password command is not the reviewed contract")
    if _section_lines(redis_block, "ports") is not None:
        raise LegacyRedisHardeningError("legacy Redis must not publish a host port")
    _legacy_redis_volume_is_safe(redis_block)
    _app_redis_environment_is_safe(blocks[LEGACY_APP_SERVICE][2])
    app_networks = _simple_networks(blocks[LEGACY_APP_SERVICE][2])
    redis_networks = _simple_networks(redis_block)
    if app_networks != redis_networks:
        raise LegacyRedisHardeningError("legacy application and Redis networks differ")
    hardened = _hardened_redis_service(image, app_networks, acl_file=acl_file)
    result = (compose_text[:redis_start] + hardened + compose_text[redis_end:]).encode("utf-8")
    validate_hardened_compose(result, acl_file=acl_file)
    return SourceContract(redis_image=image, networks=app_networks, hardened_compose=result)


def validate_hardened_compose(compose_payload, *, acl_file=ACL_FILE):
    compose_text = _decode_text(compose_payload, "hardened Compose file")
    blocks = _service_blocks(compose_text)
    if LEGACY_REDIS_SERVICE not in blocks:
        raise LegacyRedisHardeningError("hardened Redis service is missing")
    _start, _end, redis_block = blocks[LEGACY_REDIS_SERVICE]
    _forbid_unsafe_service_constructs(redis_block)
    _require_scalar(redis_block, "container_name", LEGACY_REDIS_CONTAINER)
    _require_scalar(redis_block, "user", "0:0")
    required = (
        "redis-server",
        "--aclfile",
        "/etc/redis/users.acl",
        "--appendonly",
        '"no"',
        "--save",
        '""',
        "--dir",
        "/data",
    )
    if any(value not in redis_block for value in required):
        raise LegacyRedisHardeningError("hardened Redis command is incomplete")
    forbidden = ("sh -c", "--requirepass", "${REDIS_PASSWORD", "./redis_data", "    ports:")
    if any(value in redis_block for value in forbidden):
        raise LegacyRedisHardeningError("hardened Redis command is unsafe")
    if f"{acl_file}:/etc/redis/users.acl:ro" not in redis_block:
        raise LegacyRedisHardeningError("hardened Redis ACL mount is invalid")
    for required_value in (
        "/data:rw,noexec,nosuid,nodev",
        "read_only: true",
        "- ALL",
        "no-new-privileges:true",
        "driver: \"none\"",
        "NOAUTH Authentication required",
    ):
        if required_value not in redis_block:
            raise LegacyRedisHardeningError("hardened Redis service is incomplete")


def validate_password(password, label):
    if not isinstance(password, str) or not 32 <= len(password) <= 4096:
        raise LegacyRedisHardeningError(f"{label} does not meet the password policy")
    if any(
        ord(character) < 0x21
        or ord(character) > 0x7E
        or character in FORBIDDEN_PASSWORD_CHARACTERS
        for character in password
    ):
        raise LegacyRedisHardeningError(f"{label} does not meet the password policy")


def parse_legacy_environment(payload):
    if len(payload) > MAX_ENV_BYTES:
        raise LegacyRedisHardeningError("legacy environment file is too large")
    try:
        source = payload.decode("ascii", errors="strict")
    except UnicodeError as error:
        raise LegacyRedisHardeningError("legacy environment file uses an unsafe encoding") from error
    if "\r" in source or "\x00" in source:
        raise LegacyRedisHardeningError("legacy environment file uses an unsafe encoding")
    values = {}
    lines = source.splitlines(keepends=True)
    for line in lines:
        raw = line[:-1] if line.endswith("\n") else line
        if not raw or raw.startswith("#"):
            continue
        key, separator, value = raw.partition("=")
        if (
            not separator
            or not ENV_KEY_RE.fullmatch(key)
            or key.startswith(FORBIDDEN_ENV_PREFIXES)
            or key in values
            or not value
            or any(
                ord(character) < 0x21
                or ord(character) > 0x7E
                or character in FORBIDDEN_PASSWORD_CHARACTERS
                for character in value
            )
        ):
            raise LegacyRedisHardeningError("legacy environment file is not a safe literal environment")
        values[key] = value
    password = values.get("REDIS_PASSWORD")
    if password is None:
        raise LegacyRedisHardeningError("legacy Redis password is missing")
    validate_password(password, "legacy Redis password")
    return source, values


def replace_legacy_redis_password(payload, new_password):
    validate_password(new_password, "new Redis password")
    source, values = parse_legacy_environment(payload)
    output = []
    replaced = False
    for line in source.splitlines(keepends=True):
        raw = line[:-1] if line.endswith("\n") else line
        if raw.startswith("REDIS_PASSWORD="):
            output.append(f"REDIS_PASSWORD={new_password}\n")
            replaced = True
        else:
            output.append(line)
    if not replaced or values.get("REDIS_PASSWORD") is None:
        raise LegacyRedisHardeningError("legacy Redis password is missing")
    return "".join(output).encode("ascii")


def _redis_protocol(*arguments):
    payload = [f"*{len(arguments)}\r\n".encode("ascii")]
    for argument in arguments:
        encoded = argument.encode("utf-8")
        payload.append(f"${len(encoded)}\r\n".encode("ascii"))
        payload.append(encoded + b"\r\n")
    return b"".join(payload)


class LegacyRedisHardener:
    def __init__(
        self,
        *,
        paths,
        runner=run_command,
        password_reader=None,
        health_probe=None,
        sleep=time.sleep,
        clock=time.monotonic,
        owner_uid=0,
        owner_gid=0,
        source_path_validator=None,
    ):
        self.paths = paths
        self.runner = runner
        self.password_reader = password_reader or self._read_passwords
        self.health_probe = health_probe or self._probe_app_health
        self.sleep = sleep
        self.clock = clock
        self.owner_uid = owner_uid
        self.owner_gid = owner_gid
        self.source_path_validator = source_path_validator or _require_trusted_legacy_source_path

    def _environment(self):
        return _process_environment(docker_config_dir=self.paths.docker_config_dir)

    def _run(self, argv, *, timeout=COMMAND_TIMEOUT_SECONDS, input_data=None, allow_failure=False):
        return self.runner(
            argv,
            timeout=timeout,
            environment=self._environment(),
            input_data=input_data,
            allow_failure=allow_failure,
        )

    def _docker_argv(self, *arguments):
        return [
            str(DOCKER_BINARY),
            "--host",
            "unix:///var/run/docker.sock",
            "--config",
            str(self.paths.docker_config_dir),
            *arguments,
        ]

    def _compose_argv(self, *arguments):
        return self._docker_argv(
            "compose",
            "--project-name",
            LEGACY_PROJECT,
            "--env-file",
            str(self.paths.env_file),
            "-f",
            str(self.paths.compose_file),
            *arguments,
        )

    def _read_passwords(self):
        current = getpass.getpass("Legacy Redis password: ", stream=sys.stderr)
        replacement = getpass.getpass("New Redis password: ", stream=sys.stderr)
        confirmation = getpass.getpass("Confirm new Redis password: ", stream=sys.stderr)
        if not hmac.compare_digest(replacement, confirmation):
            raise LegacyRedisHardeningError("new Redis password confirmation did not match")
        return current, replacement

    def _probe_app_health(self):
        connection = None
        try:
            connection = http.client.HTTPConnection("127.0.0.1", LEGACY_APP_PORT, timeout=5)
            connection.request("GET", "/health", headers={"Host": "localhost", "Connection": "close"})
            response = connection.getresponse()
            response.read(1024)
            if response.status != 200:
                raise LegacyRedisHardeningError("legacy application loopback health check failed")
        except (OSError, http.client.HTTPException) as error:
            raise LegacyRedisHardeningError("legacy application loopback health check failed") from error
        finally:
            if connection is not None:
                connection.close()

    def _validate_docker_binary(self):
        _require_trusted_docker_binary()

    def _pin_docker_socket(self):
        path = self.paths.docker_socket
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError as error:
            raise LegacyRedisHardeningError("local Docker socket is unavailable") from error
        if (
            path.is_symlink()
            or not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o002
        ):
            raise LegacyRedisHardeningError("local Docker socket is unsafe")

    def _prepare_docker_config(self):
        parent = self.paths.docker_config_dir.parent
        _require_directory(parent, expected_uid=self.owner_uid, expected_mode=0o700)
        _require_directory(
            self.paths.docker_config_dir,
            expected_uid=self.owner_uid,
            expected_mode=0o700,
            create=True,
        )
        try:
            entries = list(self.paths.docker_config_dir.iterdir())
        except OSError as error:
            raise LegacyRedisHardeningError("isolated Docker config directory is unavailable") from error
        if entries:
            raise LegacyRedisHardeningError("isolated Docker config directory is not empty")

    def _validate_paths(self):
        self.source_path_validator(self.paths.legacy_root, expected_uid=self.owner_uid)
        self._validate_docker_binary()
        if (
            self.paths.compose_file != self.paths.legacy_root / "docker-compose.local.yml"
            or self.paths.env_file != self.paths.legacy_root / ".env"
            or self.paths.redis_data != self.paths.legacy_root / "redis_data"
            or self.paths.state_dir.parent != self.paths.private_root
            or self.paths.acl_dir.parent != self.paths.private_root
            or self.paths.acl_file != self.paths.acl_dir / "users.acl"
        ):
            raise LegacyRedisHardeningError("legacy Redis paths are not the fixed source layout")
        try:
            root_metadata = self.paths.legacy_root.stat(follow_symlinks=False)
            resolved_root = self.paths.legacy_root.resolve(strict=True)
        except OSError as error:
            raise LegacyRedisHardeningError("legacy source directory is unavailable") from error
        if (
            self.paths.legacy_root.is_symlink()
            or resolved_root != self.paths.legacy_root
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != self.owner_uid
            or stat.S_IMODE(root_metadata.st_mode) & 0o022
        ):
            raise LegacyRedisHardeningError("legacy source directory is unsafe")
        _stat_regular(
            self.paths.compose_file,
            maximum_bytes=MAX_COMPOSE_BYTES,
            expected_uid=self.owner_uid,
            expected_mode=0o600,
        )
        _stat_regular(
            self.paths.env_file,
            maximum_bytes=MAX_ENV_BYTES,
            expected_uid=self.owner_uid,
            expected_mode=0o600,
        )
        try:
            data_metadata = self.paths.redis_data.stat(follow_symlinks=False)
            resolved_data = self.paths.redis_data.resolve(strict=True)
        except OSError as error:
            raise LegacyRedisHardeningError("legacy Redis data directory is unavailable") from error
        if (
            self.paths.redis_data.is_symlink()
            or resolved_data != self.paths.redis_data
            or not stat.S_ISDIR(data_metadata.st_mode)
        ):
            raise LegacyRedisHardeningError("legacy Redis data directory is unsafe")
        _require_directory(self.paths.private_root, expected_uid=self.owner_uid, expected_mode=0o700)
        _require_directory(self.paths.state_dir, expected_uid=self.owner_uid, expected_mode=0o700, create=True)
        _require_directory(self.paths.acl_dir, expected_uid=self.owner_uid, expected_mode=0o700, create=True)
        try:
            state_entries = list(self.paths.state_dir.iterdir())
        except OSError as error:
            raise LegacyRedisHardeningError("legacy Redis recovery directory is unavailable") from error
        if state_entries:
            raise LegacyRedisHardeningError("unfinished legacy Redis recovery state exists")
        if self.paths.acl_file.exists() or self.paths.acl_file.is_symlink():
            raise LegacyRedisHardeningError("legacy Redis ACL already exists; refusing to overwrite it")

    def _take_source_control(self):
        try:
            os.chown(self.paths.legacy_root, self.owner_uid, self.owner_gid)
            os.chmod(self.paths.legacy_root, 0o750)
        except OSError as error:
            raise LegacyRedisHardeningError("legacy source directory could not be made root-controlled") from error
        _require_directory(self.paths.legacy_root, expected_uid=self.owner_uid, expected_mode=0o750)

    def _write_recovery(self, compose, environment, data_metadata, app, redis):
        document = {
            "version": 1,
            "source_app_id": app.identity,
            "source_redis_id": redis.identity,
            "compose_sha256": hashlib.sha256(compose.data).hexdigest(),
            "environment_sha256": hashlib.sha256(environment.data).hexdigest(),
            "redis_data": {
                "uid": data_metadata.st_uid,
                "gid": data_metadata.st_gid,
                "mode": stat.S_IMODE(data_metadata.st_mode),
            },
        }
        _atomic_write(
            self.paths.state_dir / "compose.before",
            compose.data,
            mode=0o600,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
        )
        _atomic_write(
            self.paths.state_dir / "env.before",
            environment.data,
            mode=0o600,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
        )
        _atomic_write(
            self.paths.state_dir / "state.json",
            (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            mode=0o600,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
        )

    def _read_recovery(self):
        compose = _read_regular_file(
            self.paths.state_dir / "compose.before",
            maximum_bytes=MAX_COMPOSE_BYTES,
            expected_uid=self.owner_uid,
            expected_mode=0o600,
        )
        environment = _read_regular_file(
            self.paths.state_dir / "env.before",
            maximum_bytes=MAX_ENV_BYTES,
            expected_uid=self.owner_uid,
            expected_mode=0o600,
        )
        state = _read_regular_file(
            self.paths.state_dir / "state.json",
            maximum_bytes=16 * 1024,
            expected_uid=self.owner_uid,
            expected_mode=0o600,
        )
        try:
            document = json.loads(state.data.decode("ascii"))
            data = document["redis_data"]
            data_snapshot = DirectorySnapshot(
                uid=data["uid"], gid=data["gid"], mode=data["mode"]
            )
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as error:
            raise LegacyRedisHardeningError("legacy Redis recovery state is invalid") from error
        if (
            document.get("version") != 1
            or not CONTAINER_ID_RE.fullmatch(document.get("source_app_id", ""))
            or not CONTAINER_ID_RE.fullmatch(document.get("source_redis_id", ""))
            or not all(isinstance(value, int) and value >= 0 for value in dataclasses.astuple(data_snapshot))
            or data_snapshot.mode > 0o7777
            or hashlib.sha256(compose.data).hexdigest() != document.get("compose_sha256")
            or hashlib.sha256(environment.data).hexdigest() != document.get("environment_sha256")
        ):
            raise LegacyRedisHardeningError("legacy Redis recovery state is invalid")
        return compose, environment, data_snapshot

    def _clear_recovery(self):
        for name in RECOVERY_FILES:
            _safe_unlink(
                self.paths.state_dir / name,
                expected_uid=self.owner_uid,
                expected_mode=0o600,
                maximum_bytes=MAX_COMPOSE_BYTES if name == "compose.before" else MAX_ENV_BYTES,
            )

    def _clear_generated_acl(self):
        if not self.paths.acl_file.exists() and not self.paths.acl_file.is_symlink():
            return
        acl = _read_regular_file(
            self.paths.acl_file,
            maximum_bytes=16 * 1024,
            expected_uid=self.owner_uid,
            expected_mode=0o400,
        )
        validate_acl_content(acl.data)
        _safe_unlink(
            self.paths.acl_file,
            expected_uid=self.owner_uid,
            expected_mode=0o400,
            maximum_bytes=16 * 1024,
        )

    def _inspect_metadata(self, reference):
        template = (
            "{{.Id}}|{{.Name}}|{{.State.Running}}|"
            "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|"
            "{{.Config.Image}}|{{.Image}}|"
            "{{index .Config.Labels \"com.docker.compose.project\"}}|"
            "{{index .Config.Labels \"com.docker.compose.service\"}}"
        )
        result = self._run(self._docker_argv("inspect", "--format", template, reference), timeout=15)
        try:
            values = _decoded_stdout(result).split("|")
            metadata = ContainerMetadata(
                identity=values[0],
                name=values[1],
                running=values[2] == "true",
                health=values[3],
                image=values[4],
                image_identity=values[5],
                project=values[6],
                service=values[7],
            )
        except (IndexError, ValueError) as error:
            raise LegacyRedisHardeningError("legacy container runtime metadata is invalid") from error
        if (
            len(values) != 8
            or not CONTAINER_ID_RE.fullmatch(metadata.identity)
            or not metadata.name.startswith("/")
            or metadata.health not in {"none", "starting", "healthy", "unhealthy"}
            or not metadata.image
            or not IMAGE_ID_RE.fullmatch(metadata.image_identity)
            or not metadata.project
            or not metadata.service
        ):
            raise LegacyRedisHardeningError("legacy container runtime metadata is invalid")
        return metadata

    def _require_container(self, reference, *, name, service, expected_id=None, running=True):
        metadata = self._inspect_metadata(reference)
        if (
            metadata.name != f"/{name}"
            or metadata.project != LEGACY_PROJECT
            or metadata.service != service
            or metadata.running != running
            or (expected_id is not None and metadata.identity != expected_id)
        ):
            raise LegacyRedisHardeningError("legacy container identity or state changed")
        return metadata

    def _inspect_json(self, reference, template):
        result = self._run(self._docker_argv("inspect", "--format", template, reference), timeout=15)
        try:
            return json.loads(_decoded_stdout(result))
        except json.JSONDecodeError as error:
            raise LegacyRedisHardeningError("legacy container runtime metadata is invalid") from error

    def _require_no_redis_port(self, reference):
        ports = self._inspect_json(reference, "{{json .NetworkSettings.Ports}}")
        if not isinstance(ports, dict) or any(value for value in ports.values()):
            raise LegacyRedisHardeningError("legacy Redis unexpectedly publishes a host port")

    def _require_app_loopback_port(self, reference):
        ports = self._inspect_json(reference, "{{json .NetworkSettings.Ports}}")
        if ports != {
            "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]
        }:
            raise LegacyRedisHardeningError("legacy application is not bound to loopback 8080")

    def _require_legacy_redis_mount(self, reference):
        mounts = self._inspect_json(reference, "{{json .Mounts}}")
        if not isinstance(mounts, list):
            raise LegacyRedisHardeningError("legacy Redis mount metadata is invalid")
        data_mounts = [
            mount
            for mount in mounts
            if isinstance(mount, dict) and mount.get("Destination") == "/data"
        ]
        if len(data_mounts) != 1:
            raise LegacyRedisHardeningError("legacy Redis data mount is invalid")
        mount = data_mounts[0]
        if (
            mount.get("Type") != "bind"
            or mount.get("Source") != str(self.paths.redis_data)
            or mount.get("RW") is not True
        ):
            raise LegacyRedisHardeningError("legacy Redis data mount is invalid")
        if any(
            isinstance(item, dict) and item.get("Source") == "/var/run/docker.sock"
            for item in mounts
        ):
            raise LegacyRedisHardeningError("legacy Redis mount is unsafe")

    def _require_shared_network(self, app, redis):
        app_networks = self._inspect_json(app.identity, "{{json .NetworkSettings.Networks}}")
        redis_networks = self._inspect_json(redis.identity, "{{json .NetworkSettings.Networks}}")
        if not isinstance(app_networks, dict) or not isinstance(redis_networks, dict):
            raise LegacyRedisHardeningError("legacy container network metadata is invalid")
        if not set(app_networks).intersection(redis_networks):
            raise LegacyRedisHardeningError("legacy application and Redis do not share a network")

    def _require_hardened_runtime(self, app, redis, snapshot):
        if app.identity == snapshot.app.identity or redis.identity == snapshot.redis.identity:
            raise LegacyRedisHardeningError("legacy service recreation did not produce new containers")
        if app.image_identity != snapshot.app_image_identity or redis.image_identity != snapshot.redis_image_identity:
            raise LegacyRedisHardeningError("legacy service image identity changed during hardening")
        self._require_no_redis_port(redis.identity)
        self._require_app_loopback_port(app.identity)
        self._require_shared_network(app, redis)
        mounts = self._inspect_json(redis.identity, "{{json .Mounts}}")
        if not isinstance(mounts, list):
            raise LegacyRedisHardeningError("hardened Redis mount metadata is invalid")
        acl_mounts = [
            mount
            for mount in mounts
            if isinstance(mount, dict) and mount.get("Destination") == "/etc/redis/users.acl"
        ]
        if len(acl_mounts) != 1 or (
            acl_mounts[0].get("Type") != "bind"
            or acl_mounts[0].get("Source") != str(self.paths.acl_file)
            or acl_mounts[0].get("RW") is not False
        ):
            raise LegacyRedisHardeningError("hardened Redis ACL mount is invalid")
        if any(isinstance(mount, dict) and mount.get("Destination") == "/data" for mount in mounts):
            raise LegacyRedisHardeningError("hardened Redis retained the legacy data mount")
        acl = _read_regular_file(
            self.paths.acl_file,
            maximum_bytes=16 * 1024,
            expected_uid=self.owner_uid,
            expected_mode=0o400,
        )
        validate_acl_content(acl.data)
        command = self._inspect_json(redis.identity, "{{json .Config.Cmd}}")
        if (
            not isinstance(command, list)
            or any(not isinstance(value, str) for value in command)
            or "redis-server" not in command
            or "--aclfile" not in command
            or any(value == "--requirepass" or value == "sh" for value in command)
        ):
            raise LegacyRedisHardeningError("hardened Redis command is invalid")
        host_config = self._inspect_json(
            redis.identity,
            "{{json .HostConfig}}",
        )
        if not isinstance(host_config, dict):
            raise LegacyRedisHardeningError("hardened Redis host configuration is invalid")
        tmpfs = host_config.get("Tmpfs")
        cap_drop = host_config.get("CapDrop")
        security_opt = host_config.get("SecurityOpt")
        if (
            host_config.get("ReadonlyRootfs") is not True
            or not isinstance(tmpfs, dict)
            or "/data" not in tmpfs
            or not isinstance(cap_drop, list)
            or "ALL" not in cap_drop
            or not isinstance(security_opt, list)
            or "no-new-privileges:true" not in security_opt
        ):
            raise LegacyRedisHardeningError("hardened Redis host configuration is invalid")

    def _redis_ping(self, redis_id, password):
        request = _redis_protocol("AUTH", "default", password) + _redis_protocol("PING")
        result = self._run(
            self._docker_argv("exec", "--interactive", redis_id, "redis-cli", "--pipe"),
            timeout=15,
            input_data=request,
        )
        response = _decoded_stdout(result)
        if "errors: 0" not in response:
            raise LegacyRedisHardeningError("legacy Redis authenticated health check failed")

    def _wait_redis_healthy(self, expected_id=None):
        deadline = self.clock() + STARTUP_TIMEOUT_SECONDS
        while True:
            redis = self._require_container(
                LEGACY_REDIS_CONTAINER,
                name=LEGACY_REDIS_CONTAINER,
                service=LEGACY_REDIS_SERVICE,
                expected_id=expected_id,
                running=True,
            )
            if redis.health == "healthy":
                return redis
            if redis.health == "unhealthy" or self.clock() >= deadline:
                raise LegacyRedisHardeningError("hardened Redis did not become healthy")
            self.sleep(1)

    def _wait_redis_running(self):
        deadline = self.clock() + STARTUP_TIMEOUT_SECONDS
        while True:
            redis = self._require_container(
                LEGACY_REDIS_CONTAINER,
                name=LEGACY_REDIS_CONTAINER,
                service=LEGACY_REDIS_SERVICE,
                running=True,
            )
            if redis.health != "unhealthy":
                return redis
            if self.clock() >= deadline:
                raise LegacyRedisHardeningError("legacy Redis did not restart during rollback")
            self.sleep(1)

    def _wait_app_health(self):
        deadline = self.clock() + STARTUP_TIMEOUT_SECONDS
        while True:
            try:
                self.health_probe()
                return
            except LegacyRedisHardeningError:
                if self.clock() >= deadline:
                    raise LegacyRedisHardeningError("legacy application did not become healthy")
                self.sleep(1)

    def _validate_preflight(self, app_id, redis_id, contract):
        app = self._require_container(
            LEGACY_APP_CONTAINER,
            name=LEGACY_APP_CONTAINER,
            service=LEGACY_APP_SERVICE,
            expected_id=app_id,
            running=True,
        )
        redis = self._require_container(
            LEGACY_REDIS_CONTAINER,
            name=LEGACY_REDIS_CONTAINER,
            service=LEGACY_REDIS_SERVICE,
            expected_id=redis_id,
            running=True,
        )
        if redis.image != contract.redis_image:
            raise LegacyRedisHardeningError("legacy Redis image does not match the reviewed Compose contract")
        self._require_no_redis_port(redis.identity)
        self._require_app_loopback_port(app.identity)
        self._require_legacy_redis_mount(redis.identity)
        self._require_shared_network(app, redis)
        self.health_probe()
        return RuntimeSnapshot(
            app=app,
            redis=redis,
            app_image_identity=app.image_identity,
            redis_image_identity=redis.image_identity,
        )

    def _stop_service(self, service):
        self._run(self._compose_argv("stop", "--timeout", "10", service), timeout=30)

    def _start_service(self, service):
        self._run(
            self._compose_argv(
                "up",
                "--detach",
                "--no-build",
                "--pull",
                "never",
                "--force-recreate",
                "--no-deps",
                service,
            ),
            timeout=STARTUP_TIMEOUT_SECONDS,
        )

    def _secure_legacy_residue(self):
        try:
            os.chown(self.paths.redis_data, self.owner_uid, self.owner_gid)
            os.chmod(self.paths.redis_data, 0o700)
        except OSError as error:
            raise LegacyRedisHardeningError("legacy Redis residue could not be made root-only") from error
        _require_directory(self.paths.redis_data, expected_uid=self.owner_uid, expected_mode=0o700)

    def _restore_legacy_residue(self, snapshot):
        try:
            os.chown(self.paths.redis_data, snapshot.uid, snapshot.gid)
            os.chmod(self.paths.redis_data, snapshot.mode)
        except OSError as error:
            raise LegacyRedisHardeningError("legacy Redis residue could not be restored") from error

    def _rollback(self, old_password):
        compose, environment, data_snapshot = self._read_recovery()
        _atomic_write(
            self.paths.compose_file,
            compose.data,
            mode=0o600,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
            parent_mode=0o750,
        )
        _atomic_write(
            self.paths.env_file,
            environment.data,
            mode=0o600,
            owner_uid=self.owner_uid,
            owner_gid=self.owner_gid,
            parent_mode=0o750,
        )
        self._restore_legacy_residue(data_snapshot)
        self._run(
            self._compose_argv("stop", "--timeout", "10", LEGACY_APP_SERVICE, LEGACY_REDIS_SERVICE),
            timeout=45,
            allow_failure=True,
        )
        self._start_service(LEGACY_REDIS_SERVICE)
        redis = self._wait_redis_running()
        self._redis_ping(redis.identity, old_password)
        self._start_service(LEGACY_APP_SERVICE)
        self._require_container(
            LEGACY_APP_CONTAINER,
            name=LEGACY_APP_CONTAINER,
            service=LEGACY_APP_SERVICE,
            running=True,
        )
        self._wait_app_health()
        self._clear_generated_acl()
        self._clear_recovery()

    def apply(self, app_id, redis_id):
        self._validate_paths()
        self._pin_docker_socket()
        self._prepare_docker_config()
        compose = _read_regular_file(self.paths.compose_file, maximum_bytes=MAX_COMPOSE_BYTES)
        environment = _read_regular_file(self.paths.env_file, maximum_bytes=MAX_ENV_BYTES)
        _env_source, env_values = parse_legacy_environment(environment.data)
        contract = transform_compose(compose.data, acl_file=self.paths.acl_file)
        runtime = self._validate_preflight(app_id, redis_id, contract)
        current_password, new_password = self.password_reader()
        validate_password(current_password, "legacy Redis password")
        validate_password(new_password, "new Redis password")
        if not hmac.compare_digest(current_password, env_values["REDIS_PASSWORD"]):
            raise LegacyRedisHardeningError("legacy Redis password did not match the protected environment")
        if hmac.compare_digest(current_password, new_password):
            raise LegacyRedisHardeningError("new Redis password must differ from the legacy password")
        self._redis_ping(runtime.redis.identity, current_password)
        try:
            data_metadata = self.paths.redis_data.stat(follow_symlinks=False)
        except OSError as error:
            raise LegacyRedisHardeningError("legacy Redis data directory is unavailable") from error
        self._write_recovery(compose, environment, data_metadata, runtime.app, runtime.redis)
        changed = False
        try:
            self._take_source_control()
            # Verify no user-writable source raced the preflight before replacement.
            latest_compose = _read_regular_file(self.paths.compose_file, maximum_bytes=MAX_COMPOSE_BYTES)
            latest_environment = _read_regular_file(self.paths.env_file, maximum_bytes=MAX_ENV_BYTES)
            if latest_compose.data != compose.data or latest_environment.data != environment.data:
                raise LegacyRedisHardeningError("legacy source changed before the protected update")
            self._validate_preflight(app_id, redis_id, contract)
            changed = True
            _atomic_write(
                self.paths.acl_file,
                render_acl(new_password).encode("ascii"),
                mode=0o400,
                owner_uid=self.owner_uid,
                owner_gid=self.owner_gid,
            )
            _atomic_write(
                self.paths.compose_file,
                contract.hardened_compose,
                mode=0o600,
                owner_uid=self.owner_uid,
                owner_gid=self.owner_gid,
                parent_mode=0o750,
            )
            _atomic_write(
                self.paths.env_file,
                replace_legacy_redis_password(environment.data, new_password),
                mode=0o600,
                owner_uid=self.owner_uid,
                owner_gid=self.owner_gid,
                parent_mode=0o750,
            )
            self._run(self._compose_argv("config", "--quiet"), timeout=30)
            self._stop_service(LEGACY_APP_SERVICE)
            self._stop_service(LEGACY_REDIS_SERVICE)
            self._require_container(
                runtime.app.identity,
                name=LEGACY_APP_CONTAINER,
                service=LEGACY_APP_SERVICE,
                expected_id=runtime.app.identity,
                running=False,
            )
            self._require_container(
                runtime.redis.identity,
                name=LEGACY_REDIS_CONTAINER,
                service=LEGACY_REDIS_SERVICE,
                expected_id=runtime.redis.identity,
                running=False,
            )
            self._secure_legacy_residue()
            self._start_service(LEGACY_REDIS_SERVICE)
            redis = self._wait_redis_healthy()
            self._redis_ping(redis.identity, new_password)
            self._start_service(LEGACY_APP_SERVICE)
            app = self._require_container(
                LEGACY_APP_CONTAINER,
                name=LEGACY_APP_CONTAINER,
                service=LEGACY_APP_SERVICE,
                running=True,
            )
            self._require_hardened_runtime(app, redis, runtime)
            self._wait_app_health()
            self._clear_recovery()
        except BaseException as error:
            if changed:
                try:
                    self._rollback(current_password)
                except BaseException as rollback_error:
                    raise LegacyRedisHardeningError(
                        "legacy Redis hardening failed and protected recovery state was retained"
                    ) from rollback_error
            else:
                with contextlib.suppress(LegacyRedisHardeningError):
                    self._clear_recovery()
            if isinstance(error, LegacyRedisHardeningError):
                raise
            raise LegacyRedisHardeningError("legacy Redis hardening failed") from error


def parse_arguments(argv):
    arguments = list(argv)
    mode = arguments.pop(0) if arguments else "check"
    if mode not in {"check", "--apply"}:
        raise UsageError("usage: harden-legacy-redis.py [check|--apply] [container identity arguments]")
    parser = RedactedArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--source-app-container")
    parser.add_argument("--source-app-id")
    parser.add_argument("--source-redis-container")
    parser.add_argument("--source-redis-id")
    options = parser.parse_args(arguments)
    if mode == "check":
        if arguments:
            raise UsageError("check mode does not accept runtime arguments")
        return mode, options
    if (
        options.source_app_container != LEGACY_APP_CONTAINER
        or options.source_redis_container != LEGACY_REDIS_CONTAINER
        or not CONTAINER_ID_RE.fullmatch(options.source_app_id or "")
        or not CONTAINER_ID_RE.fullmatch(options.source_redis_id or "")
        or options.source_app_id == options.source_redis_id
    ):
        raise UsageError("legacy source container identity arguments are invalid")
    return mode, options


def check_contract():
    rendered = render_acl("A" * 32)
    if "A" * 32 in rendered or not re.fullmatch(
        r"user default reset on #[0-9a-f]{64} resetkeys ~\* resetchannels &\* \+@all -@admin -@dangerous\n",
        rendered,
    ):
        raise LegacyRedisHardeningError("legacy Redis ACL policy is invalid")
    sample = b"""services:
  sub2api:
    image: example/sub2api:reviewed
    container_name: sub2api
    environment:
      - REDIS_HOST=redis
      - REDIS_PASSWORD=${REDIS_PASSWORD:?required}
  redis:
    image: redis:7-alpine
    container_name: sub2api-redis
    command: >
      sh -c 'exec redis-server ${REDIS_PASSWORD:+--requirepass \"$REDIS_PASSWORD\"}'
    volumes:
      - ./redis_data:/data
"""
    transform_compose(sample)


def _run_release_guard(runner):
    runner(
        [str(RELEASE_GUARD), "check"],
        timeout=15,
        environment=_process_environment(),
        input_data=None,
        allow_failure=False,
    )


def main(
    argv=None,
    *,
    runner=run_command,
    stdin=None,
    stderr=None,
    stdout=None,
    paths=None,
    password_reader=None,
    health_probe=None,
    sleep=time.sleep,
    clock=time.monotonic,
    release_guard=_run_release_guard,
):
    stdin = sys.stdin if stdin is None else stdin
    stderr = sys.stderr if stderr is None else stderr
    stdout = sys.stdout if stdout is None else stdout
    try:
        mode, options = parse_arguments(sys.argv[1:] if argv is None else argv)
        check_contract()
        if mode == "check":
            print(
                "legacy Redis hardening contract check passed; no private file was read, "
                "no Docker command ran, and no service was changed",
                file=stdout,
            )
            return 0
        if os.geteuid() != 0:
            raise LegacyRedisHardeningError("legacy Redis hardening apply requires root")
        if not stdin.isatty() or not stdout.isatty() or not stderr.isatty():
            raise LegacyRedisHardeningError("legacy Redis hardening apply requires a private interactive terminal")
        _require_trusted_release_tree()
        selected_paths = production_paths()
        release_guard(runner)
        hardener = LegacyRedisHardener(
            paths=selected_paths,
            runner=runner,
            password_reader=password_reader,
            health_probe=health_probe,
            sleep=sleep,
            clock=clock,
            owner_uid=0,
            owner_gid=0,
        )
        hardener.apply(options.source_app_id, options.source_redis_id)
        print(
            "legacy Redis now uses a root-controlled hashed ACL and volatile data; "
            "the prior redis_data directory was retained as root-only legacy residue",
            file=stdout,
        )
        return 0
    except Exception:
        # Do not render exception text: a failed subprocess or a malformed private
        # file must never turn a password into terminal output.
        print("legacy Redis hardening failed; no password was emitted", file=stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
