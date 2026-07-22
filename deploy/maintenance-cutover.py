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
COMMAND_TERM_GRACE_SECONDS = 1
COMMAND_KILL_GRACE_SECONDS = 1
CONTAINER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
GIT_HEAD_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
PG_SYSTEM_ID_RE = re.compile(r"[0-9]{10,24}\Z")
PG_DATABASE_OID_RE = re.compile(r"[0-9]{1,10}\Z")
PG_DATABASE_NAME_HEX_RE = re.compile(r"(?:[0-9a-f]{2}){1,63}\Z")
POSTGRES_DATABASE_IDENTITY_SQL = (
    "SELECT system_identifier::text || '|' || d.oid::text || '|' || "
    "pg_catalog.encode(pg_catalog.convert_to(pg_catalog.current_database(), "
    "'UTF8'), 'hex') FROM pg_catalog.pg_control_system() "
    "CROSS JOIN pg_catalog.pg_database AS d "
    "WHERE d.datname = pg_catalog.current_database()"
)
SAFE_EXPORT_ARTIFACTS = (
    "schema_fingerprint.sha256",
    "groups.csv",
    "user_allowed_groups.csv",
    "user_subscriptions.csv",
    "api_key_metadata.csv",
    "usage_metadata.csv",
)
SAFE_EXPORT_POLICY_FILES = (
    "deploy/locked-postgres-stream.py",
    "deploy/migrate-sanitized-postgres.sh",
    "deploy/pg-env-exec.py",
    "deploy/source-postgres-exec.py",
    "deploy/prepare-app-role.sh",
    "deploy/prepare-sync-role.sh",
    "deploy/run-database-migration.sh",
    "deploy/verify-migration-totp.py",
    "deploy/verify-postgres-portability.sql",
    "deploy/verify-postgres-runtime-logging.sql",
    "deploy/verify-sanitized-target.sql",
    "migrations/000_prepare_app_role.sql",
    "migrations/000_prepare_sync_role.sql",
    "migrations/002_remove_conversation_capture.sql",
    "migrations/002_scrub_conversation_history.sql",
    "migrations/003_sync_least_privilege.sql",
    "migrations/005_app_least_privilege.sql",
    "migrations/verify_conversation_guards.sql",
    "migrations/verify_no_conversation_content.sql",
)
SAFE_EXPORT_ENTRIES = frozenset(
    (*SAFE_EXPORT_ARTIFACTS, "SHA256SUMS", "manifest.json", "COMPLETE")
)
MAX_MANIFEST_BYTES = 64 * 1024
MAX_CUTOVER_STATE_BYTES = 64 * 1024
MAX_PRIVATE_ENV_BYTES = 128 * 1024
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
    "SUB2API_SYNC_DATABASE_PASSWORD",
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
    @staticmethod
    def _process_group_exists(process_group):
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    @classmethod
    def _terminate_process_group(cls, process):
        process_group = process.pid
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process_group, signal.SIGTERM)
        grace_deadline = time.monotonic() + COMMAND_TERM_GRACE_SECONDS
        while (
            time.monotonic() < grace_deadline
            and cls._process_group_exists(process_group)
        ):
            time.sleep(0.05)
        if cls._process_group_exists(process_group):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process_group, signal.SIGKILL)
        try:
            process.communicate(timeout=COMMAND_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            try:
                process.communicate(timeout=COMMAND_KILL_GRACE_SECONDS)
            except subprocess.TimeoutExpired as error:
                raise CommandError(
                    "timed-out command process group could not be reaped"
                ) from error

    @staticmethod
    def _set_foreground_process_group(terminal_fd, process_group):
        sigttou = getattr(signal, "SIGTTOU", None)
        previous = None
        if sigttou is not None:
            previous = signal.signal(sigttou, signal.SIG_IGN)
        try:
            os.tcsetpgrp(terminal_fd, process_group)
        finally:
            if sigttou is not None:
                signal.signal(sigttou, previous)

    @classmethod
    @contextlib.contextmanager
    def _interactive_foreground(cls, process):
        try:
            terminal_fd = sys.stdin.fileno()
            if not os.isatty(terminal_fd):
                raise OSError("stdin is not a terminal")
            original_process_group = os.tcgetpgrp(terminal_fd)
            cls._set_foreground_process_group(terminal_fd, process.pid)
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGCONT)
        except (OSError, ValueError) as error:
            cls._terminate_process_group(process)
            raise CommandError(
                "interactive command could not acquire the private terminal"
            ) from error
        try:
            yield
        finally:
            try:
                cls._set_foreground_process_group(
                    terminal_fd,
                    original_process_group,
                )
            except OSError as error:
                raise CommandError(
                    "interactive command could not restore the private terminal"
                ) from error

    def __call__(
        self,
        argv,
        *,
        timeout,
        environment=None,
        allow_failure=False,
        interactive=False,
    ):
        popen_options = {
            "stdin": None if interactive else subprocess.DEVNULL,
            "stdout": None if interactive else subprocess.PIPE,
            "stderr": None if interactive else subprocess.DEVNULL,
            "env": environment,
            "start_new_session": not interactive,
        }
        if interactive:
            popen_options["preexec_fn"] = os.setpgrp
        try:
            process = subprocess.Popen(
                [str(value) for value in argv],
                **popen_options,
            )
        except OSError as error:
            raise CommandError("required local command could not be started") from error
        try:
            foreground = (
                self._interactive_foreground(process)
                if interactive
                else contextlib.nullcontext()
            )
            with foreground:
                stdout, _stderr = process.communicate(timeout=max(1, timeout))
        except subprocess.TimeoutExpired as error:
            self._terminate_process_group(process)
            raise WindowExpired("cutover command deadline exceeded") from error
        except BaseException:
            self._terminate_process_group(process)
            raise
        if self._process_group_exists(process.pid):
            self._terminate_process_group(process)
            raise CommandError("required local command left child processes running")
        if process.returncode and not allow_failure:
            raise CommandError("required local command returned a failure")
        return CommandResult(process.returncode, stdout or b"")


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


def _open_stable_absolute_file(path):
    path = pathlib.Path(path)
    components = path.parts[1:] if path.is_absolute() else ()
    if (
        not components
        or any(component in {"", ".", ".."} for component in components)
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise CutoverError("private filesystem identity path is invalid")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        directory_descriptor = os.open("/", directory_flags)
    except OSError as error:
        raise CutoverError("private filesystem identity is unavailable") from error
    try:
        for component in components[:-1]:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        parent_stat = os.fstat(directory_descriptor)
        descriptor = os.open(
            components[-1],
            file_flags,
            dir_fd=directory_descriptor,
        )
        return descriptor, parent_stat
    except OSError as error:
        raise CutoverError("private filesystem identity is unavailable") from error
    finally:
        os.close(directory_descriptor)


def _filesystem_identity(file_stat):
    return {
        "device": file_stat.st_dev,
        "inode": file_stat.st_ino,
        "mode": file_stat.st_mode,
        "links": file_stat.st_nlink,
        "uid": file_stat.st_uid,
        "gid": file_stat.st_gid,
        "size": file_stat.st_size,
        "modified_ns": file_stat.st_mtime_ns,
        "changed_ns": file_stat.st_ctime_ns,
    }


def private_environment_identity(path, *, expected_uid, expected_gid):
    descriptor, parent_stat = _open_stable_absolute_file(path)
    try:
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != expected_uid
            or stat.S_IMODE(parent_stat.st_mode) & 0o022
            or not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_nlink != 1
            or (file_stat.st_uid, file_stat.st_gid) != (expected_uid, expected_gid)
            or stat.S_IMODE(file_stat.st_mode) != 0o600
            or file_stat.st_size > MAX_PRIVATE_ENV_BYTES
        ):
            raise CutoverError("private environment filesystem identity is unsafe")
        return _filesystem_identity(file_stat)
    finally:
        os.close(descriptor)


def stable_unit_sha256(path, *, expected_uid):
    descriptor, parent_stat = _open_stable_absolute_file(path)
    digest = hashlib.sha256()
    try:
        initial = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != expected_uid
            or stat.S_IMODE(parent_stat.st_mode) & 0o022
            or not stat.S_ISREG(initial.st_mode)
            or initial.st_nlink != 1
            or initial.st_uid != expected_uid
            or stat.S_IMODE(initial.st_mode) & 0o022
            or initial.st_size > 1024 * 1024
        ):
            raise CutoverError("legacy sync unit content identity is unsafe")
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        if _filesystem_identity(os.fstat(descriptor)) != _filesystem_identity(initial):
            raise CutoverError("legacy sync unit changed while being read")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


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
        "env_file_identity",
        "sync_fragment",
        "sync_fragment_sha256",
        "legacy",
        "targets",
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
        name = value.get("name") if isinstance(value, dict) else None
        identity = value.get("identity") if isinstance(value, dict) else None
        if (
            not isinstance(value, dict)
            or set(value) != {"name", "identity"}
            or not isinstance(name, str)
            or not CONTAINER_NAME_RE.fullmatch(name)
            or not isinstance(identity, str)
            or not CONTAINER_ID_RE.fullmatch(identity)
        ):
            raise CutoverError("maintenance recovery state has invalid legacy identities")
    targets = document.get("targets")
    if (
        not isinstance(targets, dict)
        or set(targets) != set(TARGET_NAMES)
        or any(
            value is not None
            and (
                not isinstance(value, str)
                or not CONTAINER_ID_RE.fullmatch(value)
            )
            for value in targets.values()
        )
    ):
        raise CutoverError("maintenance recovery state has invalid target identities")
    target_identity_values = [
        value for value in targets.values() if value is not None
    ]
    legacy_identity_values = {
        value["identity"] for value in legacy.values()
    }
    if (
        len(target_identity_values) != len(set(target_identity_values))
        or set(target_identity_values) & legacy_identity_values
    ):
        raise CutoverError("maintenance recovery state has aliased target identities")
    env_file = document.get("env_file")
    env_file_identity = document.get("env_file_identity")
    sync_fragment = document.get("sync_fragment")
    phase = document.get("phase")
    git_head = document.get("git_head")
    sync_fragment_sha256 = document.get("sync_fragment_sha256")
    identity_fields = {
        "device",
        "inode",
        "mode",
        "links",
        "uid",
        "gid",
        "size",
        "modified_ns",
        "changed_ns",
    }
    identity_integers_valid = (
        isinstance(env_file_identity, dict)
        and set(env_file_identity) == identity_fields
        and all(
            isinstance(env_file_identity.get(name), int)
            and not isinstance(env_file_identity.get(name), bool)
            and 0 <= env_file_identity[name] <= 2**64 - 1
            for name in identity_fields
        )
    )
    if (
        document.get("version") != 3
        or not isinstance(phase, str)
        or phase not in CUTOVER_STATE_PHASES
        or not isinstance(git_head, str)
        or not GIT_HEAD_RE.fullmatch(git_head)
        or not isinstance(env_file, str)
        or not env_file.startswith("/")
        or "\x00" in env_file
        or not identity_integers_valid
        or env_file_identity["mode"] != stat.S_IFREG | 0o600
        or env_file_identity["links"] != 1
        or env_file_identity["uid"] > 2**32 - 1
        or env_file_identity["gid"] > 2**32 - 1
        or env_file_identity["size"] > MAX_PRIVATE_ENV_BYTES
        or not isinstance(sync_fragment, str)
        or not sync_fragment.startswith("/")
        or pathlib.PurePosixPath(sync_fragment).name != SYNC_UNIT
        or not isinstance(sync_fragment_sha256, str)
        or not SHA256_RE.fullmatch(sync_fragment_sha256)
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
        "source_postgres_identity",
        "artifacts",
        "policy_files",
    }:
        raise CutoverError("safe export manifest has an invalid shape")
    completed_at = manifest.get("completed_at")
    git_head = manifest.get("git_head")
    source_identity = manifest.get("source_postgres_identity")
    artifacts = manifest.get("artifacts")
    policy_files = manifest.get("policy_files")
    if (
        manifest.get("version") != 3
        or not isinstance(completed_at, str)
        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", completed_at)
        or not isinstance(git_head, str)
        or not GIT_HEAD_RE.fullmatch(git_head)
        or git_head != expected_git_head
        or not isinstance(source_identity, dict)
        or set(source_identity) != {
            "system_identifier",
            "database_oid",
            "database_name_hex",
        }
        or not isinstance(source_identity.get("system_identifier"), str)
        or not PG_SYSTEM_ID_RE.fullmatch(source_identity["system_identifier"])
        or not isinstance(source_identity.get("database_oid"), str)
        or not PG_DATABASE_OID_RE.fullmatch(source_identity["database_oid"])
        or int(source_identity["database_oid"]) > 4_294_967_295
        or not isinstance(source_identity.get("database_name_hex"), str)
        or not PG_DATABASE_NAME_HEX_RE.fullmatch(source_identity["database_name_hex"])
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
    return (
        source_identity["system_identifier"],
        source_identity["database_oid"],
        source_identity["database_name_hex"],
    )


def validate_contract():
    required = (
        DEPLOY_DIR / "require-clean-worktree.sh",
        DEPLOY_DIR / "verify-migration-totp.py",
        DEPLOY_DIR / "security-preflight.sh",
        DEPLOY_DIR / "export-safe-metadata.sh",
        DEPLOY_DIR / "install-nginx-direct-v1.py",
        DEPLOY_DIR / "locked-postgres-stream.py",
        DEPLOY_DIR / "migrate-sanitized-postgres.sh",
        DEPLOY_DIR / "migrate-app-metadata.py",
        DEPLOY_DIR / "migrate-redis-allowlist.py",
        DEPLOY_DIR / "configure-redis-migration-acl.py",
        DEPLOY_DIR / "prepare-app-role.sh",
        DEPLOY_DIR / "prepare-sync-role.sh",
        DEPLOY_DIR / "run-database-migration.sh",
        DEPLOY_DIR / "pg-env-exec.py",
        DEPLOY_DIR / "source-postgres-exec.py",
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


def validate_canary_options(options):
    canary = load_module(
        DEPLOY_DIR / "run-v1-responses-canary.py",
        "maintenance_canary_argument_gate",
    )
    try:
        approved = canary.normalize_approved_hostnames(
            (options.approved_hostname,)
        )
        endpoint = canary.validate_endpoint(options.verify_url, approved)
        canary.validate_model(options.model)
    except canary.CanaryUsageError as error:
        raise UsageError("maintenance canary arguments are invalid") from error
    if endpoint.scheme != "https" or endpoint.hostname != options.approved_hostname:
        raise UsageError("maintenance canary must use the exact approved HTTPS hostname")


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


def decode_mountinfo_path(value):
    def replace(match):
        return chr(int(match.group(1), 8))

    decoded = re.sub(r"\\([0-7]{3})", replace, value)
    path = pathlib.Path(decoded)
    if (
        "\\" in decoded
        or "\x00" in decoded
        or not path.is_absolute()
        or any(component in {"", ".", ".."} for component in path.parts[1:])
    ):
        raise CutoverError("host mount table contains an invalid path")
    return path


def read_mountpoints(path=pathlib.Path("/proc/self/mountinfo")):
    try:
        lines = pathlib.Path(path).read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise CutoverError("host mount table could not be read") from error
    mountpoints = []
    for line in lines:
        fields = line.split()
        separators = [index for index, value in enumerate(fields) if value == "-"]
        if (
            len(fields) < 10
            or len(separators) != 1
            or separators[0] < 6
            or len(fields) - separators[0] < 4
        ):
            raise CutoverError("host mount table is malformed")
        mountpoints.append(decode_mountinfo_path(fields[4]))
    if not mountpoints:
        raise CutoverError("host mount table is empty")
    return tuple(mountpoints)


def require_no_mount_boundary(path, mountpoints):
    for mountpoint in mountpoints:
        if mountpoint == path or mountpoint.is_relative_to(path):
            raise CutoverError("target reset tree contains a mount boundary")


def clear_private_directory(
    path,
    *,
    expected_uid,
    expected_gid,
    expected_mode=0o700,
    exact_path=None,
    mountpoints_reader=None,
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
    mountpoints_reader = read_mountpoints if mountpoints_reader is None else mountpoints_reader

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
        require_no_mount_boundary(path, mountpoints_reader())
        inspect_tree(root_fd, root_stat.st_dev)
        require_no_mount_boundary(path, mountpoints_reader())
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

    def switch(self, stage, *, timeout, deadline=None, clock=time.monotonic):
        def command_timeout():
            bound = timeout
            if deadline is not None:
                remaining = int(deadline - clock())
                if remaining <= 0:
                    raise WindowExpired("60-second writer-stop deadline exceeded")
                bound = min(bound, remaining)
            return max(1, bound)

        command_timeout()
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
            timeout=command_timeout(),
            environment=self.environment,
        )
        self.runner(
            ["/usr/bin/systemctl", "reload", "nginx"],
            timeout=command_timeout(),
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
        recovery_state_expected_gid=0,
        private_env_identity=None,
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
        self.recovery_state_expected_gid = recovery_state_expected_gid
        self.private_env_identity = private_env_identity
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
        self.target_identities = {name: None for name in TARGET_NAMES}
        self.recovery_identity_unavailable = False
        self.sync_fragment = None
        self.sync_fragment_sha256 = None
        self.export_source_database_identity = None
        self.git_head = None

    def recovery_state_document(self, phase):
        if (
            self.git_head is None
            or self.private_env_identity is None
            or self.sync_fragment is None
            or self.sync_fragment_sha256 is None
        ):
            raise CutoverError("maintenance recovery identity is incomplete")
        return {
            "version": 3,
            "phase": phase,
            "git_head": self.git_head,
            "env_file": str(self.options.env_file),
            "env_file_identity": self.private_env_identity,
            "sync_fragment": self.sync_fragment,
            "sync_fragment_sha256": self.sync_fragment_sha256,
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
            "targets": dict(self.target_identities),
            "target_started": self.target_started,
            "nonce_target_started": self.nonce_target_started,
            "nonce_runtime_active": self.nonce_runtime_active,
            "writers_stopped": self.writers_stopped,
            "canary_active": self.canary_active,
        }

    def persist_recovery_state(self, phase):
        if self.recovery_state_path is None:
            return
        self.require_recovery_identity()
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
        if (
            document["git_head"] != self.git_head
            or document["env_file"] != str(self.options.env_file)
        ):
            raise CutoverError("maintenance recovery state does not match this release")
        for name, service in expected_services.items():
            if document["legacy"][name] != {
                "name": service.name,
                "identity": service.identity,
            }:
                raise CutoverError("maintenance recovery state legacy identity mismatch")
        if (
            self.private_env_identity is not None
            and document["env_file_identity"] != self.private_env_identity
        ):
            self.recovery_identity_unavailable = True
        self.private_env_identity = document["env_file_identity"]
        self.target_identities = dict(document["targets"])
        self.sync_fragment = document["sync_fragment"]
        self.sync_fragment_sha256 = document["sync_fragment_sha256"]
        self.target_started = document["target_started"]
        self.nonce_target_started = document["nonce_target_started"]
        self.nonce_runtime_active = document["nonce_runtime_active"]
        self.writers_stopped = document["writers_stopped"]
        self.canary_active = document["canary_active"]

    def require_private_env_identity(self):
        if self.private_env_identity is None:
            return
        if private_environment_identity(
                self.options.env_file,
                expected_uid=self.recovery_state_expected_uid,
                expected_gid=self.recovery_state_expected_gid,
            ) != self.private_env_identity:
            raise CutoverError("maintenance private environment identity changed")

    def require_recovery_identity(self):
        if self.recovery_identity_unavailable:
            raise CutoverError("maintenance cleanup identity is unavailable")
        if self.private_env_identity is None and self.sync_fragment_sha256 is None:
            return
        self.require_private_env_identity()
        if (
            self.sync_fragment is None
            or self.sync_fragment_sha256 is None
            or stable_unit_sha256(
                self.sync_fragment,
                expected_uid=self.recovery_state_expected_uid,
            )
            != self.sync_fragment_sha256
        ):
            raise CutoverError("maintenance recovery filesystem identity changed")
        if self.unit_metadata() != self.sync_fragment:
            raise CutoverError("legacy sync unit identity changed")

    def log(self, message):
        print(message, file=self.stdout, flush=True)

    def remaining(self):
        if self.deadline is None:
            return 300
        remaining = int(self.deadline - self.clock())
        if remaining <= 0:
            raise WindowExpired("180-second maintenance window exceeded")
        return remaining

    def writer_stop_remaining(self):
        if self.writer_stop_deadline is None:
            return None
        remaining = int(self.writer_stop_deadline - self.clock())
        if remaining <= 0:
            raise WindowExpired("60-second writer-stop deadline exceeded")
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
        writer_stop_remaining = self.writer_stop_remaining()
        if writer_stop_remaining is not None:
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

    def probe_health(self, port, path, *, timeout=5):
        bound = min(timeout, self.remaining())
        writer_stop_remaining = self.writer_stop_remaining()
        if writer_stop_remaining is not None:
            bound = min(bound, writer_stop_remaining)
        self.health_probe(port, path, timeout=max(1, bound))

    def inspect_container_runtime(
        self,
        reference,
        *,
        expected_name,
        expected_identity=None,
        allow_missing=False,
    ):
        result = self.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.Id}}|{{.Name}}|{{.State.Running}}|"
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
                reference,
            ],
            timeout=10,
            allow_failure=allow_missing,
        )
        if result.returncode:
            return None
        try:
            identity, actual_name, running, health = decode_stdout(result).split("|")
        except ValueError as error:
            raise CutoverError("container identity or runtime state is invalid") from error
        if (
            not CONTAINER_ID_RE.fullmatch(identity)
            or actual_name != f"/{expected_name}"
            or (expected_identity is not None and identity != expected_identity)
            or running not in {"true", "false"}
            or health not in {"none", "starting", "healthy", "unhealthy"}
        ):
            raise CutoverError("container identity or runtime state changed")
        return identity, running == "true", health

    def docker_state(self, service):
        _identity, running, health = self.inspect_container_runtime(
            service.identity,
            expected_name=service.name,
            expected_identity=service.identity,
        )
        return running, health

    def require_legacy(self, service, *, running, healthy=False):
        actual, health = self.docker_state(service)
        if actual != running:
            raise CutoverError("legacy container runtime state is unexpected")
        if healthy and health != "healthy":
            raise CutoverError("legacy data container is not rollback-ready")

    def target_exists(self, name):
        result = self.run(
            ["docker", "inspect", "--format", "{{.Id}}", name],
            timeout=10,
            allow_failure=True,
        )
        if result.returncode:
            return False
        identity = decode_stdout(result)
        if not CONTAINER_ID_RE.fullmatch(identity):
            raise CutoverError("target container identity is invalid")
        return True

    def pin_target_identity(self, name, *, replace=False):
        if name not in self.target_identities:
            raise CutoverError("unknown migrated-target container")
        runtime = self.inspect_container_runtime(name, expected_name=name)
        identity = runtime[0]
        previous = self.target_identities[name]
        if previous is not None and previous != identity and not replace:
            raise CutoverError("migrated-target container identity changed")
        other_identities = {
            value
            for other_name, value in self.target_identities.items()
            if other_name != name and value is not None
        }
        legacy_identities = {service.identity for service in self.services.containers()}
        if identity in other_identities or identity in legacy_identities:
            raise CutoverError("migrated-target container identity aliases another service")
        self.target_identities[name] = identity
        return identity

    def target_state(self, name):
        identity = self.target_identities.get(name)
        if identity is None:
            raise CutoverError("migrated-target container identity is not pinned")
        _identity, running, health = self.inspect_container_runtime(
            identity,
            expected_name=name,
            expected_identity=identity,
        )
        return running, health

    def require_target(self, name, *, running=True, healthy=False):
        actual_running, health = self.target_state(name)
        if actual_running != running:
            raise CutoverError("migrated-target container runtime state is unexpected")
        if healthy and health != "healthy":
            raise CutoverError("migrated-target container is not healthy")

    def require_all_targets(self, *, healthy):
        for name in TARGET_NAMES:
            self.require_target(name, running=True, healthy=healthy)

    def wait_target_healthy(self, name):
        if name in self.target_identities and self.target_identities[name] is None:
            self.pin_target_identity(name)
        deadline = self.clock() + min(90, self.remaining())
        while True:
            if name in self.target_identities:
                running, health = self.target_state(name)
                if running and health == "healthy":
                    return
            else:
                result = self.run(
                    [
                        "docker",
                        "inspect",
                        "--format",
                        "{{.State.Running}}|"
                        "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
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
        self.require_private_env_identity()

        def parse_identity(result):
            try:
                system_identifier, database_oid, database_name_hex = decode_stdout(
                    result
                ).split("|")
            except ValueError as error:
                raise CutoverError("PostgreSQL endpoint identity query was invalid")
            if (
                not PG_SYSTEM_ID_RE.fullmatch(system_identifier)
                or not PG_DATABASE_OID_RE.fullmatch(database_oid)
                or int(database_oid) > 4_294_967_295
                or not PG_DATABASE_NAME_HEX_RE.fullmatch(database_name_hex)
            ):
                raise CutoverError("PostgreSQL endpoint identity query was invalid")
            return system_identifier, database_oid, database_name_hex

        source_result = self.run(
            [
                "python3",
                str(DEPLOY_DIR / "source-postgres-exec.py"),
                "--env-file",
                str(self.options.env_file),
                "--source-app-container",
                self.services.app.name,
                "--source-app-id",
                self.services.app.identity,
                "--source-postgres-container",
                self.services.postgres.name,
                "--source-postgres-id",
                self.services.postgres.identity,
                "--source-app-state",
                "running",
                "identity",
            ],
            timeout=30,
        )
        identities = {
            "SUB2API_SOURCE_DATABASE_URL": parse_identity(source_result),
        }
        self.require_private_env_identity()

        helper = DEPLOY_DIR / "pg-env-exec.py"
        pg_helper = load_module(helper, "maintenance_postgres_endpoint_gate")
        environment_name = "SUB2API_TARGET_DATABASE_URL"
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
                self.target_identities[TARGET_POSTGRES],
            ],
            timeout=10,
        )
        try:
            settings = json.loads(decode_stdout(settings_result))
        except json.JSONDecodeError as error:
            raise CutoverError("target PostgreSQL network metadata is invalid") from error
        ports = settings.get("Ports") if isinstance(settings, dict) else None
        if not isinstance(ports, dict):
            raise CutoverError("target PostgreSQL network metadata is invalid")
        bindings = ports.get("5432/tcp")
        if (
            not address.is_loopback
            or address != ipaddress.ip_address("127.0.0.1")
            or port != 15432
            or bindings != [{"HostIp": "127.0.0.1", "HostPort": "15432"}]
        ):
            raise CutoverError(
                "target PostgreSQL URL is not the exact migration port binding"
            )
        target_result = self.run(
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
                POSTGRES_DATABASE_IDENTITY_SQL,
            ],
            timeout=15,
            private_keys=(environment_name,),
        )
        identities[environment_name] = parse_identity(target_result)
        return identities

    def verify_safe_export(self):
        result = self.run(
            ["git", "-C", str(REPO_DIR), "rev-parse", "--verify", "HEAD^{commit}"],
            timeout=10,
        )
        git_head = decode_stdout(result)
        if not GIT_HEAD_RE.fullmatch(git_head):
            raise CutoverError("release Git identity is invalid")
        self.export_source_database_identity = validate_safe_export(
            self.options.safe_export_dir,
            git_head,
            expected_uid=0,
        )
        self.git_head = git_head

    def require_export_source_identity(self, database_identities):
        if (
            database_identities.get("SUB2API_SOURCE_DATABASE_URL")
            != self.export_source_database_identity
        ):
            raise CutoverError(
                "safe export belongs to a different source PostgreSQL database"
            )

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
                    self.services.redis.identity,
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

    def verify_rollback_ready(self):
        self.require_legacy(self.services.app, running=True)
        self.require_legacy(self.services.postgres, running=True, healthy=True)
        self.require_legacy(self.services.redis, running=True, healthy=True)
        if (
            self.unit_metadata() != self.sync_fragment
            or stable_unit_sha256(
                self.sync_fragment,
                expected_uid=self.recovery_state_expected_uid,
            )
            != self.sync_fragment_sha256
            or not self.unit_active()
        ):
            raise CutoverError("legacy sync service is not rollback-ready")
        self.probe_health(8080, "/health")
        self.probe_health(3021, "/healthz")
        self.nginx.require_stage("stable")

    def preflight(self):
        validate_canary_options(self.options)
        self.require_private_env_identity()
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
        self.sync_fragment_sha256 = stable_unit_sha256(
            self.sync_fragment,
            expected_uid=self.recovery_state_expected_uid,
        )
        if not self.unit_active():
            raise CutoverError("legacy sync writer must be active before maintenance")
        self.probe_health(8080, "/health")
        self.probe_health(3021, "/healthz")
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
        self.persist_recovery_state("preflight_targets_starting")
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
        self.verify_rollback_ready()
        self.log("checkpoint: exact legacy identities and target data services verified")

    def stop_writers(self):
        self.writer_stop_deadline = self.clock() + WRITER_STOP_SECONDS
        self.run(["/usr/bin/systemctl", "stop", SYNC_UNIT], timeout=20)
        if self.unit_active():
            raise CutoverError("legacy sync writer did not stop")
        if self.unit_metadata() != self.sync_fragment:
            raise CutoverError("legacy sync unit identity changed while stopping writers")
        self.run(
            ["docker", "stop", "--time", "10", self.services.app.identity],
            timeout=20,
        )
        self.require_legacy(self.services.app, running=False)
        self.require_legacy(self.services.postgres, running=True, healthy=True)
        self.require_legacy(self.services.redis, running=True, healthy=True)
        self.writers_stopped = True
        self.log("checkpoint: legacy Sub2API and sync writers stopped")

    def migrate(self):
        self.require_recovery_identity()
        self.migration_writes_stopped = True
        steps = (
            (
                [
                    str(DEPLOY_DIR / "migrate-sanitized-postgres.sh"),
                    "--apply",
                    "--env-file",
                    str(self.options.env_file),
                    "--source-app-container",
                    self.services.app.name,
                    "--source-app-id",
                    self.services.app.identity,
                    "--source-postgres-container",
                    self.services.postgres.name,
                    "--source-postgres-id",
                    self.services.postgres.identity,
                ],
                "PostgreSQL",
                (),
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
                [
                    str(DEPLOY_DIR / "prepare-sync-role.sh"),
                    "--apply",
                    "--env-file",
                    str(self.options.env_file),
                ],
                "sync database role",
                (),
            ),
            (
                [
                    str(DEPLOY_DIR / "run-database-migration.sh"),
                    "sync-role",
                    "--apply",
                    "--env-file",
                    str(self.options.env_file),
                ],
                "sync ownership schema",
                (),
            ),
            (
                [
                    str(DEPLOY_DIR / "prepare-app-role.sh"),
                    "--apply",
                    "--env-file",
                    str(self.options.env_file),
                ],
                "app database role",
                (),
            ),
        )
        for command, label, private_keys in steps:
            self.run(command, private_keys=private_keys)
            self.log(f"checkpoint: {label} migration completed")

        self.require_target(TARGET_POSTGRES, running=True, healthy=True)
        old_postgres_identity = self.target_identities[TARGET_POSTGRES]
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
        self.require_target(TARGET_POSTGRES, running=False)
        self.run(
            postgres_migration_compose_command(
                self.options.env_file,
                "rm",
                "--force",
                "traffic-canary-postgres",
            ),
            timeout=30,
        )
        if self.inspect_container_runtime(
            old_postgres_identity,
            expected_name=TARGET_POSTGRES,
            expected_identity=old_postgres_identity,
            allow_missing=True,
        ) is not None:
            raise CutoverError("old migrated-target PostgreSQL container still exists")
        self.target_identities[TARGET_POSTGRES] = None
        self.persist_recovery_state("migrating")
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
        if self.target_identities[TARGET_POSTGRES] == old_postgres_identity:
            raise CutoverError("migrated-target PostgreSQL identity was not replaced")
        self.persist_recovery_state("migrating")
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
        self.require_all_targets(healthy=True)
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
        self.probe_health(8081, "/health")
        self.log("checkpoint: sanitized traffic target and stopped-legacy identities verified")

    def switch_and_canary(self):
        if self.writer_stop_deadline is None:
            raise CutoverError("active writer-stop deadline is required")
        self.writer_stop_remaining()
        self.require_all_targets(healthy=True)
        self.probe_health(8081, "/health")
        writer_remaining = self.writer_stop_remaining()
        switch_timeout = min(15, self.remaining())
        if writer_remaining is not None:
            switch_timeout = min(switch_timeout, writer_remaining)
        self.nginx.switch(
            "canary",
            timeout=switch_timeout,
            deadline=self.writer_stop_deadline,
            clock=self.clock,
        )
        self.canary_active = True
        self.require_all_targets(healthy=True)
        self.probe_health(8081, "/health")
        self.writer_stop_remaining()
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
        self.require_all_targets(healthy=True)
        self.writer_stop_remaining()
        self.writer_stop_deadline = None
        self.log("checkpoint: target traffic restored within 60 seconds")
        self.log("checkpoint: Nginx canary upstream and metadata-only API canary passed")

    def ensure_legacy_running(self, service, *, require_healthy=False):
        running, _health = self.docker_state(service)
        if not running:
            self.runner(
                ["docker", "start", service.identity],
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

    def require_target_cleanup_identity(self):
        for name, identity in self.target_identities.items():
            if identity is None:
                if self.target_exists(name):
                    raise CutoverError(
                        "unpinned migrated-target container exists during rollback"
                    )
                continue
            runtime = self.inspect_container_runtime(
                identity,
                expected_name=name,
                expected_identity=identity,
                allow_missing=True,
            )
            if runtime is None and self.target_exists(name):
                raise CutoverError(
                    "migrated-target container name was rebound during rollback"
                )

    def require_targets_absent_after_cleanup(self):
        for name, identity in self.target_identities.items():
            if identity is not None and self.inspect_container_runtime(
                identity,
                expected_name=name,
                expected_identity=identity,
                allow_missing=True,
            ) is not None:
                raise CutoverError("traffic-canary target still exists after rollback")
            if self.target_exists(name):
                raise CutoverError("traffic-canary target name still exists after rollback")

    def rollback(self):
        self.writer_stop_deadline = None
        self.deadline = self.clock() + ROLLBACK_SECONDS
        errors = []

        def attempt(label, action):
            try:
                action()
            except Exception:
                errors.append(label)

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
        attempt("legacy_app_health", lambda: self.probe_health(8080, "/health"))

        def restore_sync():
            current_fragment = self.unit_metadata()
            if self.sync_fragment is None:
                stable_unit_sha256(
                    current_fragment,
                    expected_uid=self.recovery_state_expected_uid,
                )
            elif current_fragment != self.sync_fragment:
                raise CutoverError("legacy sync unit identity changed during rollback")
            elif (
                self.sync_fragment_sha256 is not None
                and stable_unit_sha256(
                    self.sync_fragment,
                    expected_uid=self.recovery_state_expected_uid,
                )
                != self.sync_fragment_sha256
            ):
                raise CutoverError("legacy sync unit identity changed during rollback")
            if not self.unit_active():
                self.runner(
                    ["/usr/bin/systemctl", "start", SYNC_UNIT],
                    timeout=30,
                    environment=self.environment,
                )
            if not self.unit_active():
                raise CutoverError("legacy sync unit did not start during rollback")
            self.probe_health(3021, "/healthz")

        attempt("legacy_sync_health", restore_sync)

        legacy_ready = not any(
            value in errors
            for value in (
                "legacy_postgres_start",
                "legacy_redis_start",
                "legacy_app_start",
                "legacy_app_health",
            )
        )
        stable_restored = False
        if legacy_ready:
            try:
                self.nginx.switch("stable", timeout=15)
                self.probe_health(8080, "/health")
                stable_restored = True
            except Exception:
                errors.append("stable_upstream_restore")
        else:
            errors.append("stable_upstream_not_restored_without_healthy_legacy")

        cleanup_identity_verified = False
        if stable_restored:
            try:
                self.require_recovery_identity()
                self.require_target_cleanup_identity()
                cleanup_identity_verified = True
            except Exception:
                errors.append("recovery_identity")

        traffic_isolated = not self.target_started
        nonce_isolated = not self.nonce_target_started
        if stable_restored and cleanup_identity_verified and self.target_started:
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
                self.require_targets_absent_after_cleanup()
                traffic_isolated = True
            except Exception:
                errors.append("traffic_canary_isolation")
        elif self.target_started and cleanup_identity_verified:
            errors.append("traffic_canary_kept_for_active_upstream_safety")

        if stable_restored and cleanup_identity_verified and self.nonce_target_started:
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
        elif self.nonce_target_started and cleanup_identity_verified:
            errors.append("nonce_target_kept_for_active_upstream_safety")
        if (
            stable_restored
            and cleanup_identity_verified
            and traffic_isolated
            and nonce_isolated
        ):
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
    if mode != "check" and (
        options.env_file is None or not options.env_file.is_absolute()
    ):
        raise UsageError("private environment file path must be absolute")
    if mode == "--apply" and (
        options.wrangler_config is None or not options.wrangler_config.is_absolute()
    ):
        raise UsageError("private Wrangler config path must be absolute")
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
    validate_canary_options(options)
    return mode, options, validate_options(options)


def authenticate_private_operator():
    result = subprocess.run(
        [sys.executable, str(DEPLOY_DIR / "verify-migration-totp.py")],
        env=minimal_environment(),
        check=False,
    )
    if result.returncode:
        raise CutoverError("maintenance TOTP verification failed")


def validate_private_migration_values(private_values):
    missing = REQUIRED_PRIVATE_VALUES - set(private_values)
    if missing or private_values.get("SUB2API_DATA_ROOT") != "/mnt/data/sub2api-gate":
        raise CutoverError("private migration environment is incomplete")
    if (
        private_values["SUB2API_SOURCE_DATABASE_URL"]
        == private_values["SUB2API_TARGET_DATABASE_URL"]
    ):
        raise CutoverError("source and target PostgreSQL URLs must differ")
    if (
        private_values["SUB2API_DATABASE_URL"]
        != private_values["SUB2API_TARGET_DATABASE_URL"]
    ):
        raise CutoverError("app-role and migration target PostgreSQL URLs must match")
    if private_values["SUB2API_TARGET_REDIS_USERNAME"] != "sub2api_migration":
        raise CutoverError("nonce migration target must use sub2api_migration")
    if len(private_values["SUB2API_TARGET_REDIS_PASSWORD"]) < 24:
        raise CutoverError("nonce migration target password is too short")
    if (
        private_values["SUB2API_SOURCE_REDIS_URL"]
        == private_values["SUB2API_TARGET_REDIS_URL"]
    ):
        raise CutoverError("source and target Redis URLs must differ")


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
        authenticate()
        private_env = load_module(DEPLOY_DIR / "private_env.py", "maintenance_private_env")
        expected_uid = os.geteuid()
        expected_gid = 0 if expected_uid == 0 else os.getegid()
        private_values = {}
        env_file_identity = None
        private_environment_unavailable = False
        try:
            env_file_identity = private_environment_identity(
                options.env_file,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            private_values = private_env.read_private_environment(options.env_file)
            if private_environment_identity(
                options.env_file,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            ) != env_file_identity:
                raise CutoverError("private environment changed while being loaded")
            validate_private_migration_values(private_values)
        except (CutoverError, private_env.PrivateEnvironmentError) as error:
            if mode == "--apply":
                if isinstance(error, private_env.PrivateEnvironmentError):
                    raise CutoverError(str(error)) from error
                raise
            private_values = {}
            env_file_identity = None
            private_environment_unavailable = True

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
                recovery_state_expected_gid=0,
                private_env_identity=env_file_identity,
                stdout=stdout,
            )
            if mode == "--recover":
                recovery_state_unavailable = False
                try:
                    state = load_cutover_state(CUTOVER_STATE_PATH, expected_uid=0)
                    result = runner(
                        [
                            "git",
                            "-C",
                            str(REPO_DIR),
                            "rev-parse",
                            "--verify",
                            "HEAD^{commit}",
                        ],
                        timeout=10,
                        environment=minimal_environment(),
                    )
                    controller.git_head = decode_stdout(result)
                    controller.restore_recovery_state(state)
                except CutoverError:
                    recovery_state_unavailable = True
                controller.recovery_identity_unavailable = (
                    controller.recovery_identity_unavailable
                    or private_environment_unavailable
                    or recovery_state_unavailable
                )
                with deferred_termination_signals():
                    rollback_errors = controller.rollback()
                if rollback_errors:
                    with contextlib.suppress(Exception):
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
