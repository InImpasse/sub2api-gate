#!/usr/bin/env python3
"""Bounded, fail-closed orchestration for the sanitized data cutover.

The default mode is an offline contract check. The apply path is intentionally
opinionated: the only stopped writers are the exact legacy Sub2API container
and the fixed legacy sync unit. PostgreSQL and Redis remain available for the
logical migration. Any failure starts the exact legacy identities, verifies
their loopback health, restores the fixed stable Nginx upstream, and only then
removes the traffic canary project.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass


REPO_DIR = pathlib.Path(__file__).resolve().parents[1]
DEPLOY_DIR = REPO_DIR / "deploy"
COMPOSE_FILE = REPO_DIR / "docker-compose.traffic-canary.yml"
POSTGRES_MIGRATION_COMPOSE_FILE = REPO_DIR / "docker-compose.postgres-migration.yml"
COMPOSE_PROJECT = "sub2api-gate-traffic-canary"
COMPOSE_PROFILE = "traffic-canary"
SYNC_COMPOSE_FILE = REPO_DIR / "docker-compose.sync-canary.yml"
REDIS_MIGRATION_COMPOSE_FILE = REPO_DIR / "docker-compose.redis-migration.yml"
SYNC_COMPOSE_PROJECT = "sub2api-gate-sync-canary"
SYNC_COMPOSE_PROFILE = "sync-canary"
TARGET_APP = "sub2api-traffic-canary"
TARGET_POSTGRES = "sub2api-traffic-canary-postgres"
TARGET_REDIS = "sub2api-traffic-canary-redis"
TARGET_NAMES = (TARGET_APP, TARGET_POSTGRES, TARGET_REDIS)
TARGET_NONCE_REDIS = "sub2api-sync-canary-redis-nonce"
TARGET_DATA_ROOT = pathlib.Path("/mnt/data/sub2api-gate")
SAFE_BACKUP_ROOT = TARGET_DATA_ROOT / "safe-backup"
CUTOVER_STATE_PATH = SAFE_BACKUP_ROOT / "maintenance-cutover-state.json"
SYNC_UNIT = "sub2api-sync.service"
WINDOW_SECONDS = 180
WRITER_STOP_SECONDS = 60
ROLLBACK_SECONDS = 120
CONTAINER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_HEAD_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
PG_SYSTEM_ID_RE = re.compile(r"[0-9]{10,24}\Z")
SAFE_EXPORT_ARTIFACTS = (
    "schema.sql",
    "groups.csv",
    "user_allowed_groups.csv",
    "user_subscriptions.csv",
    "api_key_metadata.csv",
    "usage_metadata.csv",
)
SAFE_EXPORT_POLICY_FILES = (
    "deploy/migrate-sanitized-postgres.sh",
    "deploy/pg-env-exec.py",
    "deploy/verify-postgres-portability.sql",
    "deploy/verify-postgres-runtime-logging.sql",
    "deploy/verify-sanitized-target.sql",
    "migrations/002_remove_conversation_capture.sql",
    "migrations/002_scrub_conversation_history.sql",
    "migrations/verify_conversation_guards.sql",
    "migrations/verify_no_conversation_content.sql",
)
SAFE_EXPORT_ENTRIES = frozenset(
    (*SAFE_EXPORT_ARTIFACTS, "SHA256SUMS", "manifest.json", "COMPLETE")
)
MAX_MANIFEST_BYTES = 64 * 1024
MAX_CUTOVER_STATE_BYTES = 64 * 1024
CUTOVER_STATE_PHASES = frozenset(
    {
        "preflight_targets_starting",
        "preflight_nonce_starting",
        "ready_to_stop_writers",
        "writers_stopped",
        "migrating",
        "starting_target",
        "switching_nginx",
        "rollback_incomplete",
    }
)

REQUIRED_PRIVATE_VALUES = {
    "SUB2API_DATA_ROOT",
    "SUB2API_SOURCE_DATABASE_URL",
    "SUB2API_TARGET_DATABASE_URL",
    "SUB2API_DATABASE_URL",
    "SUB2API_APP_DATABASE_PASSWORD",
    "SUB2API_SOURCE_REDIS_URL",
    "SUB2API_SOURCE_REDIS_PASSWORD",
    "SUB2API_TARGET_REDIS_URL",
    "SUB2API_TARGET_REDIS_PASSWORD",
    "SUB2API_TARGET_REDIS_USERNAME",
    "SUB2API_SYNC_REDIS_PASSWORD",
}


class CutoverError(RuntimeError):
    pass


class UsageError(CutoverError):
    pass


class WindowExpired(CutoverError):
    pass


class CommandError(CutoverError):
    pass


class TerminationRequested(CutoverError):
    pass


@dataclass(frozen=True)
class LegacyService:
    name: str
    identity: str


@dataclass(frozen=True)
class LegacyServices:
    app: LegacyService
    postgres: LegacyService
    redis: LegacyService

    def containers(self):
        return (self.app, self.postgres, self.redis)


@dataclass(frozen=True)
class NginxPaths:
    root: pathlib.Path
    active: pathlib.Path
    state: pathlib.Path
    site: pathlib.Path | None = None
    stable: pathlib.Path = REPO_DIR / "nginx/snippets/sub2api-upstream-stable.conf"
    canary: pathlib.Path = REPO_DIR / "nginx/snippets/sub2api-upstream-canary.conf"

    @classmethod
    def production(cls):
        root = pathlib.Path("/etc/nginx")
        return cls(
            root=root,
            active=root / "snippets/sub2api-upstream-active.conf",
            state=root / "sub2api-gate",
            site=root / "sites-enabled/sub2api.conf",
        )


@dataclass
class CommandResult:
    returncode: int
    stdout: bytes = b""


class CommandRunner:
    def __call__(
        self,
        argv,
        *,
        timeout,
        environment=None,
        allow_failure=False,
        interactive=False,
    ):
        try:
            result = subprocess.run(
                [str(value) for value in argv],
                stdin=None if interactive else subprocess.DEVNULL,
                stdout=None if interactive else subprocess.PIPE,
                stderr=None if interactive else subprocess.DEVNULL,
                env=environment,
                timeout=max(1, timeout),
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise WindowExpired("cutover command deadline exceeded") from error
        except OSError as error:
            raise CommandError("required local command could not be started") from error
        if result.returncode and not allow_failure:
            raise CommandError("required local command returned a failure")
        return CommandResult(result.returncode, result.stdout or b"")


def load_module(path, name):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise CutoverError("required local helper could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def decode_stdout(result):
    try:
        return result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise CutoverError("local command returned invalid text") from error


def _open_private_export_file(path, expected_uid):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
    except OSError as error:
        raise CutoverError("safe export contains an unavailable file") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        raise CutoverError("safe export files must be private single-link regular files")
    return descriptor, metadata


def _read_private_export_file(path, expected_uid, maximum_bytes):
    descriptor, metadata = _open_private_export_file(path, expected_uid)
    try:
        if metadata.st_size > maximum_bytes:
            raise CutoverError("safe export control file exceeds its size limit")
        chunks = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum_bytes:
            raise CutoverError("safe export control file exceeds its size limit")
        return payload
    finally:
        os.close(descriptor)


def _sha256_private_export_file(path, expected_uid):
    descriptor, _ = _open_private_export_file(path, expected_uid)
    digest = hashlib.sha256()
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _sha256_repository_file(relative_path):
    path = REPO_DIR / relative_path
    try:
        metadata = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CutoverError("safe export policy file is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or REPO_DIR.resolve(strict=True) not in resolved.parents
    ):
        raise CutoverError("safe export policy file is unsafe")
    digest = hashlib.sha256()
    try:
        with resolved.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise CutoverError("safe export policy file could not be read") from error
    return digest.hexdigest()


def _validate_cutover_state_root(path, expected_uid):
    path = pathlib.Path(path)
    if path != CUTOVER_STATE_PATH or path.parent != SAFE_BACKUP_ROOT:
        raise CutoverError("maintenance recovery state path is not fixed")
    try:
        root_stat = SAFE_BACKUP_ROOT.stat(follow_symlinks=False)
        resolved_root = SAFE_BACKUP_ROOT.resolve(strict=True)
    except OSError as error:
        raise CutoverError("maintenance recovery state directory is unavailable") from error
    if (
        SAFE_BACKUP_ROOT.is_symlink()
        or resolved_root != SAFE_BACKUP_ROOT
        or not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != expected_uid
        or stat.S_IMODE(root_stat.st_mode) != 0o700
    ):
        raise CutoverError("maintenance recovery state directory is unsafe")
    return root_stat


def _validate_cutover_state_document(document):
    expected = {
        "version",
        "phase",
        "git_head",
        "env_file",
        "sync_fragment",
        "legacy",
        "target_started",
        "nonce_target_started",
        "nonce_runtime_active",
        "writers_stopped",
        "canary_active",
    }
    if not isinstance(document, dict) or set(document) != expected:
        raise CutoverError("maintenance recovery state has an invalid shape")
    legacy = document.get("legacy")
    if not isinstance(legacy, dict) or set(legacy) != {"app", "postgres", "redis"}:
        raise CutoverError("maintenance recovery state has invalid legacy identities")
    for value in legacy.values():
        if (
            not isinstance(value, dict)
            or set(value) != {"name", "identity"}
            or not CONTAINER_NAME_RE.fullmatch(value.get("name", ""))
            or not CONTAINER_ID_RE.fullmatch(value.get("identity", ""))
        ):
            raise CutoverError("maintenance recovery state has invalid legacy identities")
    env_file = document.get("env_file")
    sync_fragment = document.get("sync_fragment")
    if (
        document.get("version") != 1
        or document.get("phase") not in CUTOVER_STATE_PHASES
        or not GIT_HEAD_RE.fullmatch(document.get("git_head", ""))
        or not isinstance(env_file, str)
        or not env_file.startswith("/")
        or "\x00" in env_file
        or not isinstance(sync_fragment, str)
        or not sync_fragment.startswith("/")
        or pathlib.PurePosixPath(sync_fragment).name != SYNC_UNIT
        or any(
            not isinstance(document.get(name), bool)
            for name in (
                "target_started",
                "nonce_target_started",
                "nonce_runtime_active",
                "writers_stopped",
                "canary_active",
            )
        )
    ):
        raise CutoverError("maintenance recovery state is invalid")
    return document


def write_cutover_state(path, document, *, expected_uid=0):
    root_stat = _validate_cutover_state_root(path, expected_uid)
    _validate_cutover_state_document(document)
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    if len(payload) > MAX_CUTOVER_STATE_BYTES:
        raise CutoverError("maintenance recovery state exceeds its size limit")
    directory_fd = os.open(
        SAFE_BACKUP_ROOT,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary = f".{pathlib.Path(path).name}.{os.getpid()}"
    descriptor = None
    try:
        current_root = os.fstat(directory_fd)
        if (current_root.st_dev, current_root.st_ino) != (
            root_stat.st_dev,
            root_stat.st_ino,
        ):
            raise CutoverError("maintenance recovery state directory changed")
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary,
            pathlib.Path(path).name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except OSError as error:
        raise CutoverError("maintenance recovery state could not be written") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=directory_fd)
        os.close(directory_fd)


def load_cutover_state(path, *, expected_uid=0):
    _validate_cutover_state_root(path, expected_uid)
    payload = _read_private_export_file(
        pathlib.Path(path), expected_uid, MAX_CUTOVER_STATE_BYTES
    )
    try:
        document = json.loads(payload.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CutoverError("maintenance recovery state is invalid") from error
    return _validate_cutover_state_document(document)


def clear_cutover_state(path, *, expected_uid=0):
    _validate_cutover_state_root(path, expected_uid)
    state_path = pathlib.Path(path)
    if not state_path.exists() and not state_path.is_symlink():
        return
    _read_private_export_file(state_path, expected_uid, MAX_CUTOVER_STATE_BYTES)
    try:
        state_path.unlink()
        directory_fd = os.open(
            SAFE_BACKUP_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        raise CutoverError("maintenance recovery state could not be cleared") from error


def validate_safe_export(export_directory, expected_git_head, *, expected_uid=0):
    export_directory = pathlib.Path(export_directory)
    if (
        not export_directory.is_absolute()
        or export_directory.parent != SAFE_BACKUP_ROOT
        or not export_directory.name.startswith("export-")
    ):
        raise CutoverError("safe export must be an explicit export directory below the fixed backup root")
    try:
        parent_metadata = SAFE_BACKUP_ROOT.stat(follow_symlinks=False)
        directory_metadata = export_directory.stat(follow_symlinks=False)
        resolved_parent = SAFE_BACKUP_ROOT.resolve(strict=True)
        resolved_directory = export_directory.resolve(strict=True)
    except OSError as error:
        raise CutoverError("safe export directory is unavailable") from error
    if (
        SAFE_BACKUP_ROOT.is_symlink()
        or export_directory.is_symlink()
        or resolved_parent != SAFE_BACKUP_ROOT
        or resolved_directory != export_directory
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or parent_metadata.st_uid != expected_uid
        or directory_metadata.st_uid != expected_uid
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or stat.S_IMODE(directory_metadata.st_mode) != 0o700
    ):
        raise CutoverError("safe export directory must be private and owned by the release operator")
    try:
        entries = {entry.name for entry in export_directory.iterdir()}
    except OSError as error:
        raise CutoverError("safe export directory could not be inspected") from error
    if entries != SAFE_EXPORT_ENTRIES:
        raise CutoverError("safe export directory has an incomplete or unexpected file set")

    manifest_raw = _read_private_export_file(
        export_directory / "manifest.json", expected_uid, MAX_MANIFEST_BYTES
    )
    try:
        manifest = json.loads(manifest_raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CutoverError("safe export manifest is invalid") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "version",
        "completed_at",
        "git_head",
        "source_postgres_system_identifier",
        "artifacts",
        "policy_files",
    }:
        raise CutoverError("safe export manifest has an invalid shape")
    completed_at = manifest.get("completed_at")
    git_head = manifest.get("git_head")
    source_system_identifier = manifest.get("source_postgres_system_identifier")
    artifacts = manifest.get("artifacts")
    policy_files = manifest.get("policy_files")
    if (
        manifest.get("version") != 1
        or not isinstance(completed_at, str)
        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", completed_at)
        or not isinstance(git_head, str)
        or not GIT_HEAD_RE.fullmatch(git_head)
        or git_head != expected_git_head
        or not isinstance(source_system_identifier, str)
        or not PG_SYSTEM_ID_RE.fullmatch(source_system_identifier)
        or not isinstance(artifacts, dict)
        or set(artifacts) != set(SAFE_EXPORT_ARTIFACTS)
        or not isinstance(policy_files, dict)
        or set(policy_files) != set(SAFE_EXPORT_POLICY_FILES)
        or any(not isinstance(value, str) or not SHA256_RE.fullmatch(value) for value in artifacts.values())
        or any(not isinstance(value, str) or not SHA256_RE.fullmatch(value) for value in policy_files.values())
    ):
        raise CutoverError("safe export manifest does not match the release contract")

    for name in SAFE_EXPORT_ARTIFACTS:
        if _sha256_private_export_file(export_directory / name, expected_uid) != artifacts[name]:
            raise CutoverError("safe export artifact hash mismatch")
    for relative_path in SAFE_EXPORT_POLICY_FILES:
        if _sha256_repository_file(relative_path) != policy_files[relative_path]:
            raise CutoverError("safe export policy hash mismatch")

    expected_sums = "".join(
        f"{artifacts[name]}  {name}\n" for name in SAFE_EXPORT_ARTIFACTS
    ).encode("ascii")
    if _read_private_export_file(
        export_directory / "SHA256SUMS", expected_uid, MAX_MANIFEST_BYTES
    ) != expected_sums:
        raise CutoverError("safe export checksum file is invalid")
    expected_complete = f"completed_at={completed_at}\n".encode("ascii")
    if _read_private_export_file(
        export_directory / "COMPLETE", expected_uid, 256
    ) != expected_complete:
        raise CutoverError("safe export completion marker is invalid")
    return source_system_identifier


def validate_contract():
    required = (
        DEPLOY_DIR / "require-clean-worktree.sh",
        DEPLOY_DIR / "verify-migration-totp.py",
        DEPLOY_DIR / "security-preflight.sh",
        DEPLOY_DIR / "export-safe-metadata.sh",
        DEPLOY_DIR / "install-nginx-direct-v1.py",
        DEPLOY_DIR / "migrate-sanitized-postgres.sh",
        DEPLOY_DIR / "migrate-app-metadata.py",
        DEPLOY_DIR / "migrate-redis-allowlist.py",
        DEPLOY_DIR / "configure-redis-migration-acl.py",
        DEPLOY_DIR / "prepare-app-role.sh",
        DEPLOY_DIR / "pg-env-exec.py",
        DEPLOY_DIR / "traffic-canary.py",
        DEPLOY_DIR / "run-v1-responses-canary.py",
        DEPLOY_DIR / "retire-legacy-data.py",
        COMPOSE_FILE,
        POSTGRES_MIGRATION_COMPOSE_FILE,
        SYNC_COMPOSE_FILE,
        REDIS_MIGRATION_COMPOSE_FILE,
    )
    for path in required:
        if not path.is_file() or path.is_symlink():
            raise CutoverError("maintenance cutover contract is incomplete")
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    for marker in (
        "name: sub2api-gate-traffic-canary",
        'container_name: sub2api-traffic-canary',
        'container_name: sub2api-traffic-canary-postgres',
        'container_name: sub2api-traffic-canary-redis',
        '"127.0.0.1:8081:8080"',
        'driver: "none"',
        "pull_policy: never",
    ):
        if marker not in compose:
            raise CutoverError("maintenance cutover Compose contract is incomplete")
    redis_migration_compose = REDIS_MIGRATION_COMPOSE_FILE.read_text(encoding="utf-8")
    for marker in (
        '"127.0.0.1:16379:6379"',
        "source: /run/sub2api-gate/redis-migration.acl",
        "target: /etc/redis/users.acl",
        "create_host_path: false",
        "sub2api_migration",
    ):
        if marker not in redis_migration_compose:
            raise CutoverError("nonce Redis migration Compose contract is incomplete")
    postgres_migration_compose = POSTGRES_MIGRATION_COMPOSE_FILE.read_text(
        encoding="utf-8"
    )
    if '"127.0.0.1:15432:5432"' not in postgres_migration_compose:
        raise CutoverError("PostgreSQL migration Compose contract is incomplete")


def validate_name(name, label):
    if not CONTAINER_NAME_RE.fullmatch(name or "") or name in TARGET_NAMES:
        raise UsageError(f"{label} is invalid or aliases the migrated target")


def validate_identity(value, label):
    if not CONTAINER_ID_RE.fullmatch(value or ""):
        raise UsageError(f"{label} must be a full Docker container ID")


def validate_options(options):
    services = LegacyServices(
        LegacyService(options.legacy_sub2api_container, options.legacy_sub2api_id),
        LegacyService(options.legacy_postgres_container, options.legacy_postgres_id),
        LegacyService(options.legacy_redis_container, options.legacy_redis_id),
    )
    labels = ("legacy Sub2API", "legacy PostgreSQL", "legacy Redis")
    for service, label in zip(services.containers(), labels):
        validate_name(service.name, f"{label} container")
        validate_identity(service.identity, f"{label} identity")
    if len({item.name for item in services.containers()}) != 3:
        raise UsageError("legacy container names must be distinct")
    if len({item.identity for item in services.containers()}) != 3:
        raise UsageError("legacy container identities must be distinct")
    return services


def compose_command(env_file, *arguments):
    return [
        "docker",
        "compose",
        "--project-name",
        COMPOSE_PROJECT,
        "--env-file",
        str(env_file),
        "-f",
        str(COMPOSE_FILE),
        "--profile",
        COMPOSE_PROFILE,
        *arguments,
    ]


def postgres_migration_compose_command(env_file, *arguments):
    command = compose_command(env_file)
    profile_index = command.index("--profile")
    return [
        *command[:profile_index],
        "-f",
        str(POSTGRES_MIGRATION_COMPOSE_FILE),
        *command[profile_index:],
        *arguments,
    ]


def nonce_compose_command(env_file, *, migration, arguments):
    command = [
        "docker",
        "compose",
        "--project-name",
        SYNC_COMPOSE_PROJECT,
        "--env-file",
        str(env_file),
        "-f",
        str(SYNC_COMPOSE_FILE),
    ]
    if migration:
        command.extend(["-f", str(REDIS_MIGRATION_COMPOSE_FILE)])
    return [*command, "--profile", SYNC_COMPOSE_PROFILE, *arguments]


def minimal_environment():
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
    }
    if "TZ" in os.environ:
        environment["TZ"] = os.environ["TZ"]
    environment["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    return environment


def probe_http(port, path, *, timeout=5):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        response.read(1)
        if not 200 <= response.status < 300:
            raise CutoverError("required loopback health endpoint is unhealthy")
    except (OSError, http.client.HTTPException) as error:
        raise CutoverError("required loopback health endpoint is unavailable") from error
    finally:
        connection.close()


@contextlib.contextmanager
def controlled_termination_signals():
    previous = {}

    def abort(_signum, _frame):
        raise TerminationRequested("maintenance termination requested")

    for signal_name in ("SIGINT", "SIGTERM", "SIGHUP"):
        signum = getattr(signal, signal_name, None)
        if signum is None:
            continue
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, abort)
    try:
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


@contextlib.contextmanager
def deferred_termination_signals():
    previous = {}
    received = set()

    def defer(signum, _frame):
        received.add(signum)

    for signal_name in ("SIGINT", "SIGTERM", "SIGHUP"):
        signum = getattr(signal, signal_name, None)
        if signum is None:
            continue
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, defer)
    try:
        yield received
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def clear_private_directory(
    path,
    *,
    expected_uid,
    expected_gid,
    expected_mode=0o700,
    exact_path=None,
):
    path = pathlib.Path(path)
    if exact_path is not None and path != pathlib.Path(exact_path):
        raise CutoverError("target reset path is not the fixed sanitized target")
    try:
        root_stat = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CutoverError("target reset directory is unavailable") from error
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISDIR(root_stat.st_mode)
        or (root_stat.st_uid, root_stat.st_gid) != (expected_uid, expected_gid)
        or stat.S_IMODE(root_stat.st_mode) != expected_mode
    ):
        raise CutoverError("target reset directory identity is unsafe")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(path, flags)

    def inspect_tree(directory_fd, root_device):
        for name in os.listdir(directory_fd):
            item = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                item.st_dev != root_device
                or (item.st_uid, item.st_gid) != (expected_uid, expected_gid)
                or stat.S_ISLNK(item.st_mode)
            ):
                raise CutoverError("target reset tree contains an unsafe entry")
            if stat.S_ISDIR(item.st_mode):
                child = os.open(name, flags, dir_fd=directory_fd)
                try:
                    inspect_tree(child, root_device)
                finally:
                    os.close(child)
            elif not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
                raise CutoverError("target reset tree contains an unsupported entry")

    def remove_tree(directory_fd, root_device):
        for name in os.listdir(directory_fd):
            item = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if item.st_dev != root_device or stat.S_ISLNK(item.st_mode):
                raise CutoverError("target reset tree changed during removal")
            if stat.S_ISDIR(item.st_mode):
                child = os.open(name, flags, dir_fd=directory_fd)
                try:
                    remove_tree(child, root_device)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=directory_fd)
            elif stat.S_ISREG(item.st_mode) and item.st_nlink == 1:
                os.unlink(name, dir_fd=directory_fd)
            else:
                raise CutoverError("target reset tree changed during removal")

    try:
        current = os.fstat(root_fd)
        if (current.st_dev, current.st_ino) != (root_stat.st_dev, root_stat.st_ino):
            raise CutoverError("target reset directory changed while opening")
        inspect_tree(root_fd, root_stat.st_dev)
        remove_tree(root_fd, root_stat.st_dev)
        os.fsync(root_fd)
        if os.listdir(root_fd):
            raise CutoverError("target reset directory is not empty after removal")
    finally:
        os.close(root_fd)


def reset_sanitized_target():
    clear_private_directory(
        TARGET_DATA_ROOT / "app",
        expected_uid=1000,
        expected_gid=1000,
        exact_path=TARGET_DATA_ROOT / "app",
    )
    clear_private_directory(
        TARGET_DATA_ROOT / "postgres",
        expected_uid=70,
        expected_gid=70,
        exact_path=TARGET_DATA_ROOT / "postgres",
    )
    clear_private_directory(
        TARGET_DATA_ROOT / "redis/nonce",
        expected_uid=999,
        expected_gid=1000,
        exact_path=TARGET_DATA_ROOT / "redis/nonce",
    )


class NginxUpstream:
    def __init__(
        self,
        paths,
        runner,
        *,
        production=True,
        environment=None,
        initial_stage="stable",
    ):
        self.paths = paths
        self.runner = runner
        self.production = production
        self.environment = minimal_environment() if environment is None else environment
        self.initial_stage = initial_stage
        self.lock_descriptor = None

    @property
    def expected_uid(self):
        return 0 if self.production else os.geteuid()

    def _directory(self, path, label):
        try:
            item = path.stat(follow_symlinks=False)
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise CutoverError(f"{label} is unavailable") from error
        if (
            path.is_symlink()
            or resolved != path
            or not stat.S_ISDIR(item.st_mode)
            or item.st_uid != self.expected_uid
            or stat.S_IMODE(item.st_mode) & 0o022
        ):
            raise CutoverError(f"{label} is unsafe")

    def _file(self, path, label):
        try:
            item = path.stat(follow_symlinks=False)
        except OSError as error:
            raise CutoverError(f"{label} is unavailable") from error
        if (
            path.is_symlink()
            or not stat.S_ISREG(item.st_mode)
            or item.st_uid != self.expected_uid
            or stat.S_IMODE(item.st_mode) & 0o022
        ):
            raise CutoverError(f"{label} is unsafe")
        return item

    def __enter__(self):
        self._directory(self.paths.root, "Nginx root")
        self._directory(self.paths.active.parent, "Nginx snippets directory")
        if not self.paths.state.exists():
            self.paths.state.mkdir(mode=0o700)
        self._directory(self.paths.state, "Nginx operation state directory")
        self._file(self.paths.active, "active Nginx upstream")
        lock_path = self.paths.state / "nginx-operation.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(lock_path, flags, 0o600)
            lock_stat = os.fstat(descriptor)
            path_stat = os.stat(lock_path, follow_symlinks=False)
            if (
                not stat.S_ISREG(lock_stat.st_mode)
                or lock_stat.st_uid != self.expected_uid
                or stat.S_IMODE(lock_stat.st_mode) & 0o177
                or (lock_stat.st_dev, lock_stat.st_ino)
                != (path_stat.st_dev, path_stat.st_ino)
            ):
                raise CutoverError("Nginx operation lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            if "descriptor" in locals():
                os.close(descriptor)
            raise CutoverError("another Nginx operation is already in progress") from error
        except Exception:
            if "descriptor" in locals():
                os.close(descriptor)
            raise
        self.lock_descriptor = descriptor
        if self.initial_stage is not None:
            self.require_stage(self.initial_stage)
        return self

    def __exit__(self, *_arguments):
        if self.lock_descriptor is not None:
            os.close(self.lock_descriptor)
            self.lock_descriptor = None

    def stage_bytes(self, stage):
        path = self.paths.stable if stage == "stable" else self.paths.canary
        expected = (
            b"server 127.0.0.1:8080;\n"
            if stage == "stable"
            else b"server 127.0.0.1:8081;\n"
        )
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise CutoverError("tracked Nginx upstream is unavailable") from error
        if payload != expected:
            raise CutoverError("tracked Nginx upstream is not the reviewed fixed target")
        return payload

    def require_stage(self, stage):
        self._file(self.paths.active, "active Nginx upstream")
        if self.paths.active.read_bytes() != self.stage_bytes(stage):
            raise CutoverError(f"active Nginx upstream is not the fixed {stage} target")

    def verify_live_direct_v1(self, hostname):
        verifier = load_module(
            DEPLOY_DIR / "install-nginx-direct-v1.py",
            "maintenance_nginx_direct_gate",
        )
        site = self.paths.site or self.paths.root / "sites-enabled/sub2api.conf"
        try:
            verifier.verify_live_direct_v1(
                self.paths.root,
                site,
                hostname,
                production=self.production,
            )
        except Exception as error:
            raise CutoverError("live Nginx /v1 path is not the reviewed capture-free direct proxy") from error
        self.require_stage("stable")

    def switch(self, stage, *, timeout):
        payload = self.stage_bytes(stage)
        directory_descriptor = os.open(
            self.paths.active.parent,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        temporary = f".{self.paths.active.name}.cutover-{os.getpid()}"
        descriptor = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o644,
                dir_fd=directory_descriptor,
            )
            os.write(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(
                temporary,
                self.paths.active.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            os.fsync(directory_descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
        self._file(self.paths.active, "active Nginx upstream")
        self.runner(
            ["/usr/sbin/nginx", "-t"],
            timeout=timeout,
            environment=self.environment,
        )
        self.runner(
            ["/usr/bin/systemctl", "reload", "nginx"],
            timeout=timeout,
            environment=self.environment,
        )
        self.require_stage(stage)


class MaintenanceController:
    def __init__(
        self,
        *,
        options,
        services,
        private_values,
        runner,
        nginx,
        health_probe=probe_http,
        clock=time.monotonic,
        sleeper=time.sleep,
        target_resetter=reset_sanitized_target,
        recovery_state_path=None,
        recovery_state_expected_uid=0,
        stdout=None,
    ):
        self.options = options
        self.services = services
        self.private_values = private_values
        self.runner = runner
        self.nginx = nginx
        self.health_probe = health_probe
        self.clock = clock
        self.sleeper = sleeper
        self.target_resetter = target_resetter
        self.recovery_state_path = recovery_state_path
        self.recovery_state_expected_uid = recovery_state_expected_uid
        self.stdout = sys.stdout if stdout is None else stdout
        self.environment = minimal_environment()
        self.migration_writes_stopped = False
        self.deadline = None
        self.writer_stop_deadline = None
        self.target_started = False
        self.nonce_target_started = False
        self.nonce_runtime_active = False
        self.writers_stopped = False
        self.canary_active = False
        self.sync_fragment = None
        self.export_source_system_identifier = None
        self.git_head = None

    def recovery_state_document(self, phase):
        if self.git_head is None or self.sync_fragment is None:
            raise CutoverError("maintenance recovery identity is incomplete")
        return {
            "version": 1,
            "phase": phase,
            "git_head": self.git_head,
            "env_file": str(self.options.env_file),
            "sync_fragment": self.sync_fragment,
            "legacy": {
                "app": {
                    "name": self.services.app.name,
                    "identity": self.services.app.identity,
                },
                "postgres": {
                    "name": self.services.postgres.name,
                    "identity": self.services.postgres.identity,
                },
                "redis": {
                    "name": self.services.redis.name,
                    "identity": self.services.redis.identity,
                },
            },
            "target_started": self.target_started,
            "nonce_target_started": self.nonce_target_started,
            "nonce_runtime_active": self.nonce_runtime_active,
            "writers_stopped": self.writers_stopped,
            "canary_active": self.canary_active,
        }

    def persist_recovery_state(self, phase):
        if self.recovery_state_path is None:
            return
        write_cutover_state(
            self.recovery_state_path,
            self.recovery_state_document(phase),
            expected_uid=self.recovery_state_expected_uid,
        )

    def clear_recovery_state(self):
        if self.recovery_state_path is None:
            return
        clear_cutover_state(
            self.recovery_state_path,
            expected_uid=self.recovery_state_expected_uid,
        )

    def restore_recovery_state(self, document):
        expected_services = {
            "app": self.services.app,
            "postgres": self.services.postgres,
            "redis": self.services.redis,
        }
        if document["git_head"] != self.git_head or document["env_file"] != str(
            self.options.env_file
        ):
            raise CutoverError("maintenance recovery state does not match this release")
        for name, service in expected_services.items():
            if document["legacy"][name] != {
                "name": service.name,
                "identity": service.identity,
            }:
                raise CutoverError("maintenance recovery state legacy identity mismatch")
        self.sync_fragment = document["sync_fragment"]
        self.target_started = document["target_started"]
        self.nonce_target_started = document["nonce_target_started"]
        self.nonce_runtime_active = document["nonce_runtime_active"]
        self.writers_stopped = document["writers_stopped"]
        self.canary_active = document["canary_active"]

    def log(self, message):
        print(message, file=self.stdout, flush=True)

    def remaining(self):
        if self.deadline is None:
            return 300
        remaining = int(self.deadline - self.clock())
        if remaining <= 0:
            raise WindowExpired("180-second maintenance window exceeded")
        return remaining

    def run(
        self,
        argv,
        *,
        timeout=None,
        allow_failure=False,
        interactive=False,
        private_keys=(),
    ):
        bound = self.remaining() if timeout is None else min(timeout, self.remaining())
        if self.writer_stop_deadline is not None:
            writer_stop_remaining = int(self.writer_stop_deadline - self.clock())
            if writer_stop_remaining <= 0:
                raise WindowExpired("60-second writer-stop deadline exceeded")
            bound = min(bound, writer_stop_remaining)
        environment = self.environment.copy()
        for key in private_keys:
            if key not in self.private_values:
                raise CutoverError("required private step value is unavailable")
            environment[key] = self.private_values[key]
        if self.migration_writes_stopped:
            environment["SUB2API_MIGRATION_WRITES_STOPPED"] = "YES"
        return self.runner(
            argv,
            timeout=max(1, bound),
            environment=environment,
            allow_failure=allow_failure,
            interactive=interactive,
        )

    def docker_state(self, service):
        result = self.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.Id}}|{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                service.name,
            ],
            timeout=10,
        )
        identity, separator, remainder = decode_stdout(result).partition("|")
        running, separator2, health = remainder.partition("|")
        if (
            not separator
            or not separator2
            or identity != service.identity
            or running not in {"true", "false"}
            or health not in {"none", "starting", "healthy", "unhealthy"}
        ):
            raise CutoverError("legacy container identity or runtime state changed")
        return running == "true", health

    def require_legacy(self, service, *, running):
        actual, _health = self.docker_state(service)
        if actual != running:
            raise CutoverError("legacy container runtime state is unexpected")

    def target_exists(self, name):
        result = self.run(
            ["docker", "inspect", "--format", "{{.Id}}", name],
            timeout=10,
            allow_failure=True,
        )
        return result.returncode == 0

    def wait_target_healthy(self, name):
        deadline = self.clock() + min(90, self.remaining())
        while True:
            result = self.run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                    name,
                ],
                timeout=10,
            )
            if decode_stdout(result) == "true|healthy":
                return
            if self.clock() >= deadline:
                raise CutoverError("migrated-target container did not become healthy")
            self.sleeper(1)

    def unit_metadata(self):
        result = self.run(
            [
                "/usr/bin/systemctl",
                "show",
                SYNC_UNIT,
                "--property=Id",
                "--property=LoadState",
                "--property=FragmentPath",
            ],
            timeout=10,
        )
        values = {}
        for line in decode_stdout(result).splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in values:
                raise CutoverError("legacy sync unit metadata is invalid")
            values[key] = value
        fragment = values.get("FragmentPath", "")
        if (
            values.get("Id") != SYNC_UNIT
            or values.get("LoadState") != "loaded"
            or not fragment.startswith("/")
            or pathlib.PurePosixPath(fragment).name != SYNC_UNIT
        ):
            raise CutoverError("legacy sync unit identity is invalid")
        return fragment

    def unit_active(self):
        result = self.run(
            ["/usr/bin/systemctl", "is-active", "--quiet", SYNC_UNIT],
            timeout=10,
            allow_failure=True,
        )
        if result.returncode not in {0, 3}:
            raise CutoverError("legacy sync unit state could not be verified")
        return result.returncode == 0

    def verify_database_connections(self):
        helper = DEPLOY_DIR / "pg-env-exec.py"
        pg_helper = load_module(helper, "maintenance_postgres_endpoint_gate")
        endpoints = (
            (
                "SUB2API_SOURCE_DATABASE_URL",
                self.services.postgres.name,
                None,
            ),
            (
                "SUB2API_TARGET_DATABASE_URL",
                TARGET_POSTGRES,
                15432,
            ),
        )
        identities = {}
        for environment_name, container, fixed_loopback_port in endpoints:
            parsed = pg_helper.libpq_environment(
                {environment_name: self.private_values[environment_name]},
                environment_name,
            )
            try:
                address = ipaddress.ip_address(parsed["PGHOST"])
                port = int(parsed["PGPORT"])
            except (KeyError, ValueError) as error:
                raise CutoverError("PostgreSQL migration endpoint is invalid") from error
            settings_result = self.run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{json .NetworkSettings}}",
                    container,
                ],
                timeout=10,
            )
            settings = json.loads(decode_stdout(settings_result))
            addresses = {
                ipaddress.ip_address(item["IPAddress"])
                for item in settings.get("Networks", {}).values()
                if isinstance(item, dict) and item.get("IPAddress")
            }
            if address.is_loopback:
                bindings = settings.get("Ports", {}).get("5432/tcp")
                if bindings != [{"HostIp": "127.0.0.1", "HostPort": str(port)}]:
                    raise CutoverError(
                        "PostgreSQL loopback URL is not the exact container port binding"
                    )
                if fixed_loopback_port is not None and port != fixed_loopback_port:
                    raise CutoverError("target PostgreSQL must use the fixed migration port")
            elif fixed_loopback_port is not None or address not in addresses:
                raise CutoverError(
                    "PostgreSQL URL is not an exact local container endpoint"
                )
            result = self.run(
                [
                    "python3",
                    str(helper),
                    environment_name,
                    "psql",
                    "--no-psqlrc",
                    "--quiet",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "--command",
                    "SELECT system_identifier::text FROM pg_control_system()",
                ],
                timeout=15,
                private_keys=(environment_name,),
            )
            identity = decode_stdout(result)
            if not PG_SYSTEM_ID_RE.fullmatch(identity):
                raise CutoverError("PostgreSQL endpoint identity query was invalid")
            identities[environment_name] = identity
        return identities

    def verify_safe_export(self):
        result = self.run(
            ["git", "-C", str(REPO_DIR), "rev-parse", "--verify", "HEAD^{commit}"],
            timeout=10,
        )
        git_head = decode_stdout(result)
        if not GIT_HEAD_RE.fullmatch(git_head):
            raise CutoverError("release Git identity is invalid")
        self.export_source_system_identifier = validate_safe_export(
            self.options.safe_export_dir,
            git_head,
            expected_uid=0,
        )
        self.git_head = git_head

    def require_export_source_identity(self, database_identities):
        if (
            database_identities.get("SUB2API_SOURCE_DATABASE_URL")
            != self.export_source_system_identifier
        ):
            raise CutoverError("safe export belongs to a different source PostgreSQL cluster")

    def verify_legacy_redis_source(self):
        migration = load_module(
            DEPLOY_DIR / "migrate-redis-allowlist.py",
            "maintenance_redis_source_gate",
        )
        try:
            endpoint = migration.parse_redis_url(
                self.private_values["SUB2API_SOURCE_REDIS_URL"],
                "source",
            )
            address = ipaddress.ip_address(endpoint.host)
            networks_result = self.run(
                [
                    "docker",
                    "inspect",
                    "--format",
                    "{{json .NetworkSettings}}",
                    self.services.redis.name,
                ],
                timeout=10,
            )
            network_settings = json.loads(decode_stdout(networks_result))
            networks = network_settings.get("Networks", {})
            container_addresses = {
                ipaddress.ip_address(item["IPAddress"])
                for item in networks.values()
                if isinstance(item, dict) and item.get("IPAddress")
            }
            if address.is_loopback:
                bindings = network_settings.get("Ports", {}).get("6379/tcp")
                if bindings != [
                    {"HostIp": "127.0.0.1", "HostPort": str(endpoint.port)}
                ]:
                    raise CutoverError(
                        "legacy Redis loopback source is not the exact container port binding"
                    )
            elif address not in container_addresses:
                raise CutoverError(
                    "legacy Redis source is not an exact local container endpoint"
                )

            deadline = self.clock() + 15
            username = self.private_values.get("SUB2API_SOURCE_REDIS_USERNAME") or None
            with migration.RedisConnection(
                endpoint,
                self.private_values["SUB2API_SOURCE_REDIS_PASSWORD"],
                deadline,
                username,
            ) as source:
                if source.execute("PING") != b"PONG":
                    raise CutoverError("legacy Redis source PING failed")
                source_info = migration.parse_info(source.execute("INFO", "server"))
            run_id = source_info.get("run_id", "")
            version = source_info.get("redis_version", "")
            if not re.fullmatch(r"[0-9a-f]{40}", run_id) or not re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+", version
            ):
                raise CutoverError("legacy Redis source identity is invalid")
        except CutoverError:
            raise
        except Exception as error:
            raise CutoverError("legacy Redis source attestation failed") from error

    def preflight(self):
        self.verify_safe_export()
        self.nginx.verify_live_direct_v1(self.options.approved_hostname)
        traffic_canary = load_module(
            DEPLOY_DIR / "traffic-canary.py",
            "maintenance_runtime_image_gate",
        )
        try:
            traffic_canary.require_local_runtime_images(runner=self.run)
        except traffic_canary.CanaryError as error:
            raise CutoverError("reviewed runtime images are not preloaded locally") from error
        retirement_paths = (
            self.options.legacy_app_path,
            self.options.legacy_postgres_path,
            self.options.legacy_redis_path,
            self.options.legacy_nginx_log_path,
        )
        if any(not path.is_absolute() for path in retirement_paths):
            raise CutoverError("legacy retirement paths must be explicit absolute paths")
        self.run(
            [
                "python3",
                str(DEPLOY_DIR / "retire-legacy-data.py"),
                "verify-record",
                "--legacy-app-path",
                str(self.options.legacy_app_path),
                "--legacy-postgres-path",
                str(self.options.legacy_postgres_path),
                "--legacy-redis-path",
                str(self.options.legacy_redis_path),
                "--legacy-nginx-log-path",
                str(self.options.legacy_nginx_log_path),
                "--legacy-sub2api-container",
                self.services.app.name,
                "--legacy-postgres-container",
                self.services.postgres.name,
                "--legacy-redis-container",
                self.services.redis.name,
            ],
            timeout=30,
        )
        for service in self.services.containers():
            self.require_legacy(service, running=True)
        self.verify_legacy_redis_source()
        if any(self.target_exists(name) for name in (*TARGET_NAMES, TARGET_NONCE_REDIS)):
            raise CutoverError("traffic-canary target must be absent before maintenance apply")
        self.sync_fragment = self.unit_metadata()
        if not self.unit_active():
            raise CutoverError("legacy sync writer must be active before maintenance")
        self.health_probe(8080, "/health")
        self.health_probe(3021, "/healthz")
        self.nginx.require_stage("stable")

        self.run(
            postgres_migration_compose_command(
                self.options.env_file, "config", "--quiet"
            ),
            timeout=30,
        )
        self.target_started = True
        self.persist_recovery_state("preflight_targets_starting")
        self.run(
            postgres_migration_compose_command(
                self.options.env_file,
                "up",
                "--detach",
                "--no-build",
                "--pull",
                "never",
                "traffic-canary-postgres",
                "traffic-canary-redis",
            ),
            timeout=120,
        )
        self.wait_target_healthy(TARGET_POSTGRES)
        self.wait_target_healthy(TARGET_REDIS)
        database_identities = self.verify_database_connections()
        self.require_export_source_identity(database_identities)

        target_redis = urllib.parse.urlsplit(
            self.private_values["SUB2API_TARGET_REDIS_URL"]
        )
        if (
            target_redis.scheme != "redis"
            or target_redis.hostname != "127.0.0.1"
            or target_redis.port != 16379
            or target_redis.username is not None
            or target_redis.password is not None
        ):
            raise CutoverError(
                "nonce migration target must be the fixed redis://127.0.0.1:16379 endpoint"
            )
        self.run(
            [
                "python3",
                str(DEPLOY_DIR / "configure-redis-migration-acl.py"),
                "--apply",
                "--env-file",
                str(self.options.env_file),
            ],
            timeout=30,
        )
        self.nonce_target_started = True
        self.persist_recovery_state("preflight_nonce_starting")
        self.run(
            nonce_compose_command(
                self.options.env_file,
                migration=True,
                arguments=(
                    "up",
                    "--detach",
                    "--no-build",
                    "--pull",
                    "never",
                    "sync-canary-redis-nonce",
                ),
            ),
            timeout=90,
        )
        self.wait_target_healthy(TARGET_NONCE_REDIS)
        self.log("checkpoint: exact legacy identities and target data services verified")

    def stop_writers(self):
        self.writer_stop_deadline = self.clock() + WRITER_STOP_SECONDS
        try:
            self.run(["/usr/bin/systemctl", "stop", SYNC_UNIT], timeout=20)
            if self.unit_active():
                raise CutoverError("legacy sync writer did not stop")
            if self.unit_metadata() != self.sync_fragment:
                raise CutoverError("legacy sync unit identity changed while stopping writers")
            self.run(
                ["docker", "stop", "--time", "10", self.services.app.name],
                timeout=20,
            )
            self.require_legacy(self.services.app, running=False)
            self.require_legacy(self.services.postgres, running=True)
            self.require_legacy(self.services.redis, running=True)
            self.writers_stopped = True
            self.log(
                "checkpoint: legacy Sub2API and sync writers stopped within 60 seconds"
            )
        finally:
            self.writer_stop_deadline = None

    def migrate(self):
        self.migration_writes_stopped = True
        steps = (
            (
                [str(DEPLOY_DIR / "migrate-sanitized-postgres.sh"), "--apply"],
                "PostgreSQL",
                ("SUB2API_SOURCE_DATABASE_URL", "SUB2API_TARGET_DATABASE_URL"),
            ),
            (
                ["python3", str(DEPLOY_DIR / "migrate-redis-allowlist.py"), "--apply"],
                "Redis nonce",
                (
                    "SUB2API_DATA_ROOT",
                    "SUB2API_SOURCE_REDIS_URL",
                    "SUB2API_SOURCE_REDIS_PASSWORD",
                    "SUB2API_TARGET_REDIS_URL",
                    "SUB2API_TARGET_REDIS_PASSWORD",
                    "SUB2API_TARGET_REDIS_USERNAME",
                ),
            ),
            (
                ["python3", str(DEPLOY_DIR / "migrate-app-metadata.py"), "--apply"],
                "app metadata",
                tuple(
                    key
                    for key in (
                        "SUB2API_DATA_ROOT",
                        "SUB2API_COPY_MODEL_PRICING",
                        "SUB2API_SOURCE_APP_DIR",
                    )
                    if key in self.private_values
                ),
            ),
            (
                [str(DEPLOY_DIR / "prepare-app-role.sh"), "--apply"],
                "app database role",
                ("SUB2API_DATABASE_URL", "SUB2API_APP_DATABASE_PASSWORD"),
            ),
        )
        for command, label, private_keys in steps:
            self.run(command, private_keys=private_keys)
            self.log(f"checkpoint: {label} migration completed")

        self.run(
            postgres_migration_compose_command(
                self.options.env_file,
                "stop",
                "--timeout",
                "10",
                "traffic-canary-postgres",
            ),
            timeout=30,
        )
        self.run(
            postgres_migration_compose_command(
                self.options.env_file,
                "rm",
                "--force",
                "traffic-canary-postgres",
            ),
            timeout=30,
        )
        self.run(
            compose_command(
                self.options.env_file,
                "up",
                "--detach",
                "--no-build",
                "--pull",
                "never",
                "traffic-canary-postgres",
                "traffic-canary-redis",
            ),
            timeout=90,
        )
        self.wait_target_healthy(TARGET_POSTGRES)
        self.wait_target_healthy(TARGET_REDIS)
        self.log("checkpoint: target PostgreSQL migration port was removed")

        self.run(
            nonce_compose_command(
                self.options.env_file,
                migration=True,
                arguments=("stop", "--timeout", "10", "sync-canary-redis-nonce"),
            ),
            timeout=30,
        )
        self.run(
            nonce_compose_command(
                self.options.env_file,
                migration=True,
                arguments=("rm", "--force", "sync-canary-redis-nonce"),
            ),
            timeout=30,
        )
        self.run(
            [
                "python3",
                str(DEPLOY_DIR / "configure-redis-migration-acl.py"),
                "--remove",
            ],
            timeout=15,
        )
        self.run(
            nonce_compose_command(
                self.options.env_file,
                migration=False,
                arguments=(
                    "up",
                    "--detach",
                    "--no-build",
                    "--pull",
                    "never",
                    "sync-canary-redis-nonce",
                ),
            ),
            timeout=90,
        )
        self.wait_target_healthy(TARGET_NONCE_REDIS)
        self.nonce_runtime_active = True
        self.log("checkpoint: nonce Redis restarted without the migration user or port")

    def start_target(self):
        self.run(
            compose_command(
                self.options.env_file,
                "up",
                "--detach",
                "--no-build",
                "--pull",
                "never",
                "sub2api-traffic-canary",
            ),
            timeout=120,
        )
        self.wait_target_healthy(TARGET_APP)
        command = [
            "python3",
            str(DEPLOY_DIR / "traffic-canary.py"),
            "verify-stopped",
            "--legacy-sub2api-container",
            self.services.app.name,
            "--legacy-postgres-container",
            self.services.postgres.name,
            "--legacy-redis-container",
            self.services.redis.name,
            "--legacy-sub2api-id",
            self.services.app.identity,
            "--legacy-postgres-id",
            self.services.postgres.identity,
            "--legacy-redis-id",
            self.services.redis.identity,
        ]
        self.run(command, timeout=45)
        self.health_probe(8081, "/health")
        self.log("checkpoint: sanitized traffic target and stopped-legacy identities verified")

    def switch_and_canary(self):
        self.health_probe(8081, "/health")
        self.nginx.switch("canary", timeout=min(15, self.remaining()))
        self.canary_active = True
        self.health_probe(8081, "/health")
        command = [
            "python3",
            str(DEPLOY_DIR / "run-v1-responses-canary.py"),
            "--apply",
            "--url",
            self.options.verify_url,
            "--model",
            self.options.model,
            "--approved-hostname",
            self.options.approved_hostname,
        ]
        self.run(command, interactive=True)
        self.log("checkpoint: Nginx canary upstream and metadata-only API canary passed")

    def ensure_legacy_running(self, service, *, require_healthy=False):
        running, _health = self.docker_state(service)
        if not running:
            self.runner(
                ["docker", "start", service.name],
                timeout=30,
                environment=self.environment,
            )
        deadline = self.clock() + 60
        while True:
            running, health = self.docker_state(service)
            if running:
                if not require_healthy or health == "healthy":
                    return
                if health == "none":
                    raise CutoverError(
                        "exact legacy data container has no Docker healthcheck"
                    )
            if self.clock() >= deadline:
                if require_healthy:
                    raise CutoverError(
                        "exact legacy data container did not become healthy during rollback"
                    )
                raise CutoverError("exact legacy container did not start during rollback")
            self.sleeper(1)

    def rollback(self):
        errors = []

        def attempt(label, action):
            try:
                action()
            except Exception:
                errors.append(label)

        self.deadline = self.clock() + ROLLBACK_SECONDS
        attempt(
            "legacy_postgres_start",
            lambda: self.ensure_legacy_running(
                self.services.postgres,
                require_healthy=True,
            ),
        )
        attempt(
            "legacy_redis_start",
            lambda: self.ensure_legacy_running(
                self.services.redis,
                require_healthy=True,
            ),
        )
        attempt("legacy_app_start", lambda: self.ensure_legacy_running(self.services.app))
        attempt("legacy_app_health", lambda: self.health_probe(8080, "/health"))

        def restore_sync():
            if self.unit_metadata() != self.sync_fragment:
                raise CutoverError("legacy sync unit identity changed during rollback")
            if not self.unit_active():
                self.runner(
                    ["/usr/bin/systemctl", "start", SYNC_UNIT],
                    timeout=30,
                    environment=self.environment,
                )
            if not self.unit_active():
                raise CutoverError("legacy sync unit did not start during rollback")
            self.health_probe(3021, "/healthz")

        attempt("legacy_sync_health", restore_sync)

        legacy_ready = not any(
            value in errors
            for value in (
                "legacy_postgres_start",
                "legacy_redis_start",
                "legacy_app_start",
                "legacy_app_health",
                "legacy_sync_health",
            )
        )
        stable_restored = False
        if legacy_ready:
            try:
                self.nginx.switch("stable", timeout=15)
                self.health_probe(8080, "/health")
                stable_restored = True
            except Exception:
                errors.append("stable_upstream_restore")
        else:
            errors.append("stable_upstream_not_restored_without_healthy_legacy")

        traffic_isolated = not self.target_started
        nonce_isolated = not self.nonce_target_started
        if stable_restored and self.target_started:
            try:
                self.runner(
                    compose_command(
                        self.options.env_file,
                        "down",
                        "--remove-orphans",
                        "--timeout",
                        "10",
                    ),
                    timeout=60,
                    environment=self.environment,
                )
                for name in TARGET_NAMES:
                    if self.target_exists(name):
                        raise CutoverError("traffic-canary target still exists after rollback")
                traffic_isolated = True
            except Exception:
                errors.append("traffic_canary_isolation")
        elif self.target_started:
            errors.append("traffic_canary_kept_for_active_upstream_safety")

        if stable_restored and self.nonce_target_started:
            try:
                self.runner(
                    nonce_compose_command(
                        self.options.env_file,
                        migration=False,
                        arguments=("down", "--remove-orphans", "--timeout", "10"),
                    ),
                    timeout=60,
                    environment=self.environment,
                )
                if self.target_exists(TARGET_NONCE_REDIS):
                    raise CutoverError("nonce Redis target still exists after rollback")
                self.runner(
                    [
                        "python3",
                        str(DEPLOY_DIR / "configure-redis-migration-acl.py"),
                        "--remove",
                    ],
                    timeout=15,
                    environment=self.environment,
                )
                nonce_isolated = True
            except Exception:
                errors.append("nonce_target_isolation")
        elif self.nonce_target_started:
            errors.append("nonce_target_kept_for_active_upstream_safety")
        if stable_restored and traffic_isolated and nonce_isolated:
            try:
                self.target_resetter()
            except Exception:
                errors.append("sanitized_target_reset")
        return errors

    def execute(self):
        persist_state = getattr(self, "persist_recovery_state", lambda _phase: None)
        clear_state = getattr(self, "clear_recovery_state", lambda: None)
        original_error = None
        try:
            self.preflight()
            persist_state("ready_to_stop_writers")
            self.deadline = self.clock() + WINDOW_SECONDS
            self.stop_writers()
            persist_state("writers_stopped")
            persist_state("migrating")
            self.migrate()
            persist_state("starting_target")
            self.start_target()
            persist_state("switching_nginx")
            self.switch_and_canary()
            self.remaining()
            self.log("maintenance cutover completed within 180 seconds")
            clear_state()
            return
        except (Exception, KeyboardInterrupt) as error:
            original_error = error

        deferred_signals = set()
        if self.target_started or self.writers_stopped:
            with deferred_termination_signals() as deferred_signals:
                rollback_errors = self.rollback()
        else:
            rollback_errors = []
        if deferred_signals or isinstance(
            original_error,
            (KeyboardInterrupt, TerminationRequested),
        ):
            reason = "interrupted"
        elif isinstance(original_error, WindowExpired):
            reason = "deadline_exceeded"
        else:
            reason = "phase_failed"
        if rollback_errors:
            with contextlib.suppress(Exception):
                self.persist_recovery_state("rollback_incomplete")
            raise CutoverError(
                f"cutover_{reason}; rollback_incomplete=" + ",".join(rollback_errors)
            ) from original_error
        clear_state()
        raise CutoverError(f"cutover_{reason}; rollback_verified") from original_error


def parse_arguments(argv):
    arguments = list(argv)
    mode = (
        arguments.pop(0)
        if arguments and arguments[0] in {"check", "--apply", "--recover"}
        else "check"
    )
    parser = argparse.ArgumentParser(allow_abbrev=False, add_help=False)
    parser.add_argument("--env-file", type=pathlib.Path)
    parser.add_argument("--wrangler-config", type=pathlib.Path)
    parser.add_argument("--safe-export-dir", type=pathlib.Path)
    parser.add_argument("--legacy-sub2api-container")
    parser.add_argument("--legacy-sub2api-id")
    parser.add_argument("--legacy-postgres-container")
    parser.add_argument("--legacy-postgres-id")
    parser.add_argument("--legacy-redis-container")
    parser.add_argument("--legacy-redis-id")
    parser.add_argument("--legacy-app-path", type=pathlib.Path)
    parser.add_argument("--legacy-postgres-path", type=pathlib.Path)
    parser.add_argument("--legacy-redis-path", type=pathlib.Path)
    parser.add_argument("--legacy-nginx-log-path", type=pathlib.Path)
    parser.add_argument("--verify-url")
    parser.add_argument("--model")
    parser.add_argument("--approved-hostname")
    try:
        options = parser.parse_args(arguments)
    except SystemExit as error:
        raise UsageError("invalid maintenance cutover arguments") from error
    if mode == "check":
        if arguments:
            raise UsageError("check mode does not accept runtime arguments")
        return mode, options, None
    if mode == "--recover":
        required = (
            options.env_file,
            options.legacy_sub2api_container,
            options.legacy_sub2api_id,
            options.legacy_postgres_container,
            options.legacy_postgres_id,
            options.legacy_redis_container,
            options.legacy_redis_id,
        )
        forbidden = (
            options.wrangler_config,
            options.safe_export_dir,
            options.legacy_app_path,
            options.legacy_postgres_path,
            options.legacy_redis_path,
            options.legacy_nginx_log_path,
            options.verify_url,
            options.model,
            options.approved_hostname,
        )
        if not all(required) or any(forbidden):
            raise UsageError(
                "--recover requires only the private env and exact legacy container identities"
            )
        return mode, options, validate_options(options)
    required = (
        options.env_file,
        options.wrangler_config,
        options.safe_export_dir,
        options.legacy_sub2api_container,
        options.legacy_sub2api_id,
        options.legacy_postgres_container,
        options.legacy_postgres_id,
        options.legacy_redis_container,
        options.legacy_redis_id,
        options.legacy_app_path,
        options.legacy_postgres_path,
        options.legacy_redis_path,
        options.legacy_nginx_log_path,
        options.verify_url,
        options.model,
        options.approved_hostname,
    )
    if not all(required):
        raise UsageError("--apply requires private config, canary, and exact legacy identity arguments")
    return mode, options, validate_options(options)


def authenticate_private_operator():
    result = subprocess.run(
        [sys.executable, str(DEPLOY_DIR / "verify-migration-totp.py")],
        env=minimal_environment(),
        check=False,
    )
    if result.returncode:
        raise CutoverError("maintenance TOTP verification failed")


def main(
    argv=None,
    *,
    runner=None,
    stdin=None,
    stderr=None,
    stdout=None,
    authenticate=authenticate_private_operator,
    nginx_paths=None,
    production=True,
):
    argv = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin if stdin is None else stdin
    stderr = sys.stderr if stderr is None else stderr
    stdout = sys.stdout if stdout is None else stdout
    runner = CommandRunner() if runner is None else runner
    try:
        mode, options, services = parse_arguments(argv)
        validate_contract()
        if mode == "check":
            print(
                "maintenance cutover contract check passed; no private file was read, "
                "no Docker/systemd/Nginx command ran, and no service or data changed",
                file=stdout,
            )
            return 0
        if os.geteuid() != 0:
            raise CutoverError("maintenance apply/recovery must run as root")
        if not stdin.isatty() or not stderr.isatty():
            raise CutoverError("maintenance apply/recovery requires a private interactive terminal")

        runner(
            [str(DEPLOY_DIR / "require-clean-worktree.sh"), "check"],
            timeout=15,
            environment=minimal_environment(),
        )
        private_env = load_module(DEPLOY_DIR / "private_env.py", "maintenance_private_env")
        try:
            private_values = private_env.read_private_environment(options.env_file)
        except private_env.PrivateEnvironmentError as error:
            raise CutoverError(str(error)) from error
        missing = REQUIRED_PRIVATE_VALUES - set(private_values)
        if missing or private_values.get("SUB2API_DATA_ROOT") != "/mnt/data/sub2api-gate":
            raise CutoverError("private migration environment is incomplete")
        if private_values["SUB2API_SOURCE_DATABASE_URL"] == private_values["SUB2API_TARGET_DATABASE_URL"]:
            raise CutoverError("source and target PostgreSQL URLs must differ")
        if private_values["SUB2API_DATABASE_URL"] != private_values["SUB2API_TARGET_DATABASE_URL"]:
            raise CutoverError("app-role and migration target PostgreSQL URLs must match")
        if private_values["SUB2API_TARGET_REDIS_USERNAME"] != "sub2api_migration":
            raise CutoverError("nonce migration target must use sub2api_migration")
        if len(private_values["SUB2API_TARGET_REDIS_PASSWORD"]) < 24:
            raise CutoverError("nonce migration target password is too short")
        if private_values["SUB2API_SOURCE_REDIS_URL"] == private_values["SUB2API_TARGET_REDIS_URL"]:
            raise CutoverError("source and target Redis URLs must differ")

        if mode == "--apply":
            if CUTOVER_STATE_PATH.exists() or CUTOVER_STATE_PATH.is_symlink():
                raise CutoverError(
                    "unfinished maintenance recovery state exists; run --recover first"
                )
            runner(
                [
                    str(DEPLOY_DIR / "security-preflight.sh"),
                    "check",
                    "--env-file",
                    str(options.env_file),
                    "--wrangler-config",
                    str(options.wrangler_config),
                ],
                timeout=60,
                environment=minimal_environment(),
            )
        authenticate()
        paths = NginxPaths.production() if nginx_paths is None else nginx_paths
        with NginxUpstream(
            paths,
            runner,
            production=production,
            environment=minimal_environment(),
            initial_stage="stable" if mode == "--apply" else None,
        ) as nginx:
            controller = MaintenanceController(
                options=options,
                services=services,
                private_values=private_values,
                runner=runner,
                nginx=nginx,
                recovery_state_path=CUTOVER_STATE_PATH,
                recovery_state_expected_uid=0,
                stdout=stdout,
            )
            if mode == "--recover":
                state = load_cutover_state(CUTOVER_STATE_PATH, expected_uid=0)
                result = runner(
                    ["git", "-C", str(REPO_DIR), "rev-parse", "--verify", "HEAD^{commit}"],
                    timeout=10,
                    environment=minimal_environment(),
                )
                controller.git_head = decode_stdout(result)
                controller.restore_recovery_state(state)
                with deferred_termination_signals():
                    rollback_errors = controller.rollback()
                if rollback_errors:
                    controller.persist_recovery_state("rollback_incomplete")
                    raise CutoverError(
                        "maintenance_recovery_incomplete=" + ",".join(rollback_errors)
                    )
                controller.clear_recovery_state()
                print("maintenance recovery restored the exact stable services", file=stdout)
            else:
                with controlled_termination_signals():
                    controller.execute()
        return 0
    except UsageError as error:
        print(str(error), file=stderr)
        return 2
    except CutoverError as error:
        print(str(error), file=stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
