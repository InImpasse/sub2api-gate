#!/usr/bin/python3 -I
"""Install a reversible systemd sandbox for the fixed legacy sync service.

The legacy service is a root-owned Python process which binds only loopback
TCP 3021, makes normal TCP connections to its existing PostgreSQL and Redis
dependencies, and starts the local ``psql`` client.  This controller therefore
does not impose a network namespace, an IP allowlist, or an address-family
filter: those can change the existing database and Redis connectivity.  The
drop-in instead removes unneeded kernel and privilege surfaces, makes the
service code read-only, and isolates temporary files.

Apply is intentionally narrow.  It never changes the original unit, its User,
environment file, credentials, data, or network routing.  If restart or the
bounded loopback health probe fails, the controller removes only the drop-in it
created, reloads systemd, and restarts the original unit before returning an
opaque failure.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import http.client
import ipaddress
import os
import pathlib
import re
import secrets
import signal
import stat
import subprocess
import sys
import time


REPO_DIR = pathlib.Path(__file__).resolve().parents[1]
TRUSTED_FILESYSTEM_ROOT = pathlib.Path("/")
TRUSTED_RELEASE_PARENT = pathlib.Path("/opt")
TRUSTED_RELEASE_ROOT = TRUSTED_RELEASE_PARENT / "sub2api-gate-release"
CONTROLLER_SOURCE_RELATIVE_PATH = pathlib.Path("deploy/harden-legacy-sync-service.py")
CLEAN_WORKTREE_RELATIVE_PATH = pathlib.Path("deploy/require-clean-worktree.sh")
CLEAN_WORKTREE = TRUSTED_RELEASE_ROOT / CLEAN_WORKTREE_RELATIVE_PATH
SYSTEMCTL = "/usr/bin/systemctl"
BASH = "/bin/bash"
UNIT_NAME = "sub2api-sync.service"
EXPECTED_UNIT_PATH = pathlib.Path("/etc/systemd/system/sub2api-sync.service")
EXPECTED_WORKING_DIRECTORY = pathlib.Path("/opt/sub2api-sync")
EXPECTED_ENTRY_SCRIPT = EXPECTED_WORKING_DIRECTORY / "sub2api_sync.py"
EXPECTED_ENVIRONMENT_FILE = pathlib.Path("/etc/sub2api-sync.env")
EXPECTED_PYTHON = pathlib.Path("/usr/bin/python3")
RUNTIME_TRUST_ROOT = pathlib.Path("/")
DOCKER_SOCKET = pathlib.Path("/var/run/docker.sock")
PRIVATE_ROOT = pathlib.Path("/mnt/data/sub2api-gate/private")
DROPIN_DIRECTORY = pathlib.Path("/etc/systemd/system/sub2api-sync.service.d")
DROPIN_PATH = DROPIN_DIRECTORY / "99-sub2api-gate-hardening.conf"
SYNC_PORT = 3021
TCP4_FAMILY = 4
TCP6_FAMILY = 6
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
MAX_UNIT_BYTES = 256 * 1024
MAX_HEALTH_RESPONSE_BYTES = 4096
COMMAND_TIMEOUT_SECONDS = 30
RESTART_TIMEOUT_SECONDS = 45
HEALTH_TIMEOUT_SECONDS = 45
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# These settings are intentionally limited to filesystem, privilege, and
# kernel-isolation controls.  In particular, do not add PrivateNetwork,
# IPAddressDeny, or RestrictAddressFamilies here: the legacy service retains
# its reviewed PostgreSQL/Redis and loopback client connections until cutover.
HARDENING_DROPIN = b"""[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
ReadOnlyPaths=/opt/sub2api-sync
InaccessiblePaths=/var/run/docker.sock /mnt/data/sub2api-gate/private
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
LockPersonality=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077
"""

EXPECTED_EFFECTIVE_PROPERTIES = {
    "NoNewPrivileges": "yes",
    "PrivateTmp": "yes",
    "ProtectSystem": "full",
    "ProtectHome": "yes",
    "ReadOnlyPaths": str(EXPECTED_WORKING_DIRECTORY),
    "InaccessiblePaths": f"{DOCKER_SOCKET} {PRIVATE_ROOT}",
    "ProtectControlGroups": "yes",
    "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes",
    "ProtectKernelLogs": "yes",
    "LockPersonality": "yes",
    "RestrictSUIDSGID": "yes",
    "RestrictRealtime": "yes",
    "RestrictNamespaces": "yes",
    "SystemCallArchitectures": "native",
    "CapabilityBoundingSet": "",
    "AmbientCapabilities": "",
    "UMask": "0077",
}


class LegacySyncHardeningError(RuntimeError):
    pass


class OperationInterrupted(LegacySyncHardeningError):
    pass



class DropinFinalizationError(LegacySyncHardeningError):
    def __init__(self, snapshot):
        super().__init__("legacy sync hardening drop-in finalization failed")
        self.snapshot = snapshot


class RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise LegacySyncHardeningError("legacy sync hardening command validation failed")


@dataclasses.dataclass(frozen=True)
class HardeningPaths:
    repo_dir: pathlib.Path
    trusted_release_root: pathlib.Path
    clean_worktree: pathlib.Path
    unit_path: pathlib.Path
    working_directory: pathlib.Path
    entry_script: pathlib.Path
    environment_file: pathlib.Path
    runtime_trust_root: pathlib.Path
    dropin_directory: pathlib.Path
    dropin_path: pathlib.Path
    trusted_unit_directories: tuple[pathlib.Path, ...]
    proc_root: pathlib.Path
    expected_uid: int = 0
    expected_gid: int = 0


@dataclasses.dataclass(frozen=True)
class FileSnapshot:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    size: int
    digest: str


@dataclasses.dataclass(frozen=True)
class UnitInfo:
    main_pid: int
    user: str
    working_directory: str
    fragment_snapshot: FileSnapshot


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes = b""


def production_paths():
    return HardeningPaths(
        repo_dir=REPO_DIR,
        trusted_release_root=TRUSTED_RELEASE_ROOT,
        clean_worktree=CLEAN_WORKTREE,
        unit_path=EXPECTED_UNIT_PATH,
        working_directory=EXPECTED_WORKING_DIRECTORY,
        entry_script=EXPECTED_ENTRY_SCRIPT,
        environment_file=EXPECTED_ENVIRONMENT_FILE,
        runtime_trust_root=RUNTIME_TRUST_ROOT,
        dropin_directory=DROPIN_DIRECTORY,
        dropin_path=DROPIN_PATH,
        trusted_unit_directories=(
            pathlib.Path("/"),
            pathlib.Path("/etc"),
            pathlib.Path("/etc/systemd"),
            pathlib.Path("/etc/systemd/system"),
        ),
        proc_root=pathlib.Path("/proc"),
    )


def safe_environment():
    return {
        "PATH": SAFE_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "SYSTEMD_COLORS": "0",
    }


def run_command(command, *, timeout=COMMAND_TIMEOUT_SECONDS):
    try:
        result = subprocess.run(
            command,
            cwd=REPO_DIR,
            env=safe_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LegacySyncHardeningError("required local service command failed") from error
    stdout = result.stdout if isinstance(result.stdout, bytes) else b""
    return CommandResult(result.returncode, stdout)


def invoke(runner, command, *, timeout=COMMAND_TIMEOUT_SECONDS, allow_failure=False):
    try:
        result = runner(command, timeout=timeout)
    except LegacySyncHardeningError:
        raise
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LegacySyncHardeningError("required local service command failed") from error
    stdout = getattr(result, "stdout", b"")
    if isinstance(stdout, str):
        stdout = stdout.encode("utf-8", "replace")
    if not isinstance(stdout, bytes) or len(stdout) > MAX_COMMAND_OUTPUT_BYTES:
        raise LegacySyncHardeningError("local service command output is invalid")
    returncode = getattr(result, "returncode", None)
    if not isinstance(returncode, int):
        raise LegacySyncHardeningError("local service command result is invalid")
    if returncode != 0 and not allow_failure:
        raise LegacySyncHardeningError("required local service command failed")
    return CommandResult(returncode, stdout)


def _require_trusted_directory(path, expected_uid, expected_gid):
    try:
        metadata = pathlib.Path(path).lstat()
    except OSError as error:
        raise LegacySyncHardeningError("legacy sync unit directory is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or pathlib.Path(path).is_symlink()
    ):
        raise LegacySyncHardeningError("legacy sync unit directory is unsafe")


def require_trusted_unit_directories(paths):
    for directory in paths.trusted_unit_directories:
        _require_trusted_directory(directory, paths.expected_uid, paths.expected_gid)


def _require_trusted_runtime_directory_chain(root, target, expected_uid, expected_gid):
    root = pathlib.Path(root)
    target = pathlib.Path(target)
    if not root.is_absolute() or not target.is_absolute():
        raise LegacySyncHardeningError("legacy sync runtime path is unsafe")
    try:
        relative = target.relative_to(root)
    except ValueError as error:
        raise LegacySyncHardeningError("legacy sync runtime path is unsafe") from error
    if any(component in {"", ".", ".."} for component in relative.parts):
        raise LegacySyncHardeningError("legacy sync runtime path is unsafe")
    current = root
    _require_trusted_directory(current, expected_uid, expected_gid)
    for component in relative.parts:
        current = current / component
        _require_trusted_directory(current, expected_uid, expected_gid)


def _require_trusted_runtime_file(
    path, *, expected_uid, expected_gid, expected_mode=None
):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise LegacySyncHardeningError("legacy sync runtime file is unavailable") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not target.is_absolute()
        or target.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or mode & 0o022
        or (expected_mode is not None and mode != expected_mode)
    ):
        raise LegacySyncHardeningError("legacy sync runtime file is unsafe")


def require_trusted_runtime_paths(paths):
    working_directory = pathlib.Path(paths.working_directory)
    entry_script = pathlib.Path(paths.entry_script)
    environment_file = pathlib.Path(paths.environment_file)
    if entry_script.parent != working_directory:
        raise LegacySyncHardeningError("legacy sync runtime path is unsafe")
    _require_trusted_runtime_directory_chain(
        paths.runtime_trust_root,
        working_directory,
        paths.expected_uid,
        paths.expected_gid,
    )
    _require_trusted_runtime_directory_chain(
        paths.runtime_trust_root,
        environment_file.parent,
        paths.expected_uid,
        paths.expected_gid,
    )
    _require_trusted_runtime_file(
        entry_script,
        expected_uid=paths.expected_uid,
        expected_gid=paths.expected_gid,
    )
    _require_trusted_runtime_file(
        environment_file,
        expected_uid=paths.expected_uid,
        expected_gid=paths.expected_gid,
        expected_mode=0o600,
    )


def read_trusted_regular_file(path, *, expected_uid, expected_gid, expected_mode, maximum_bytes):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LegacySyncHardeningError("legacy sync service file is unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_gid != expected_gid
            or stat.S_IMODE(before.st_mode) != expected_mode
            or before.st_nlink != 1
            or before.st_size > maximum_bytes
        ):
            raise LegacySyncHardeningError("legacy sync service file is unsafe")
        payload = os.read(descriptor, maximum_bytes + 1)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or len(payload) > maximum_bytes
            or (before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode, before.st_size)
            != (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode, after.st_size)
        ):
            raise LegacySyncHardeningError("legacy sync service file changed during inspection")
    finally:
        os.close(descriptor)
    return payload, FileSnapshot(
        device=before.st_dev,
        inode=before.st_ino,
        uid=before.st_uid,
        gid=before.st_gid,
        mode=stat.S_IMODE(before.st_mode),
        size=before.st_size,
        digest=hashlib.sha256(payload).hexdigest(),
    )


def read_unit_fragment(paths):
    require_trusted_unit_directories(paths)
    return read_trusted_regular_file(
        paths.unit_path,
        expected_uid=paths.expected_uid,
        expected_gid=paths.expected_gid,
        expected_mode=0o644,
        maximum_bytes=MAX_UNIT_BYTES,
    )


def parse_properties(raw, expected_names):
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise LegacySyncHardeningError("legacy sync service metadata is invalid") from error
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in expected_names or key in values:
            raise LegacySyncHardeningError("legacy sync service metadata is invalid")
        values[key] = value
    if set(values) != set(expected_names):
        raise LegacySyncHardeningError("legacy sync service metadata is invalid")
    return values


def systemctl_properties(runner, property_names):
    command = [SYSTEMCTL, "show", UNIT_NAME]
    command.extend(f"--property={name}" for name in property_names)
    result = invoke(runner, command, timeout=COMMAND_TIMEOUT_SECONDS)
    return parse_properties(result.stdout, property_names)


def validate_effective_exec_start(value, entry_script):
    if not value.startswith("{ ") or not value.endswith(" }"):
        raise LegacySyncHardeningError("legacy sync effective command is invalid")
    body = value[2:-2]
    if "{" in body or "}" in body or "\n" in body or "\r" in body:
        raise LegacySyncHardeningError("legacy sync effective command is invalid")
    fields = {}
    for item in body.split(" ; "):
        key, separator, field_value = item.partition("=")
        if not separator or not key or key in fields:
            raise LegacySyncHardeningError("legacy sync effective command is invalid")
        fields[key] = field_value
    expected = {
        "path": str(EXPECTED_PYTHON),
        "argv[]": f"{EXPECTED_PYTHON} {entry_script}",
        "ignore_errors": "no",
    }
    if any(fields.get(key) != expected_value for key, expected_value in expected.items()):
        raise LegacySyncHardeningError("legacy sync effective command is invalid")


def validate_effective_environment_files(value, environment_file):
    if value != f"{environment_file} (ignore_errors=no)":
        raise LegacySyncHardeningError(
            "legacy sync effective environment file is invalid"
        )


def inspect_unit_configuration(paths, *, require_active, runner=run_command):
    names = (
        "Id",
        "LoadState",
        "FragmentPath",
        "ActiveState",
        "SubState",
        "MainPID",
        "User",
        "WorkingDirectory",
        "ExecStart",
        "EnvironmentFiles",
    )
    values = systemctl_properties(runner, names)
    if (
        values["Id"] != UNIT_NAME
        or values["LoadState"] != "loaded"
        or values["FragmentPath"] != str(paths.unit_path)
        or values["User"] not in {"", "root"}
        or values["WorkingDirectory"] != str(paths.working_directory)
    ):
        raise LegacySyncHardeningError("legacy sync unit identity or state is invalid")
    validate_effective_exec_start(values["ExecStart"], paths.entry_script)
    validate_effective_environment_files(
        values["EnvironmentFiles"], paths.environment_file
    )
    require_trusted_runtime_paths(paths)
    if require_active and (
        values["ActiveState"] != "active"
        or values["SubState"] != "running"
        or not re.fullmatch(r"[1-9][0-9]{0,9}", values["MainPID"])
    ):
        raise LegacySyncHardeningError("legacy sync unit identity or state is invalid")
    _payload, snapshot = read_unit_fragment(paths)
    return UnitInfo(
        main_pid=int(values["MainPID"]) if require_active else 0,
        user=values["User"],
        working_directory=values["WorkingDirectory"],
        fragment_snapshot=snapshot,
    )


def inspect_active_unit(paths, *, runner=run_command):
    return inspect_unit_configuration(paths, require_active=True, runner=runner)


def validate_restart_contract(paths, expected_snapshot, *, runner=run_command):
    unit = inspect_unit_configuration(paths, require_active=False, runner=runner)
    if unit.fragment_snapshot != expected_snapshot:
        raise LegacySyncHardeningError("legacy sync unit changed during hardening")


def validate_dropin_contract():
    try:
        text = HARDENING_DROPIN.decode("ascii")
    except UnicodeDecodeError as error:
        raise LegacySyncHardeningError("legacy sync hardening contract is invalid") from error
    lines = text.splitlines()
    if not lines or lines[0] != "[Service]" or text != "\n".join(lines) + "\n":
        raise LegacySyncHardeningError("legacy sync hardening contract is invalid")
    directives = {}
    for line in lines[1:]:
        key, separator, value = line.partition("=")
        if not separator or not key or key in directives:
            raise LegacySyncHardeningError("legacy sync hardening contract is invalid")
        directives[key] = value
    prohibited = {
        "User",
        "Group",
        "Environment",
        "EnvironmentFile",
        "ExecStart",
        "ExecStartPre",
        "ExecStartPost",
        "PrivateNetwork",
        "IPAddressAllow",
        "IPAddressDeny",
        "RestrictAddressFamilies",
    }
    if prohibited.intersection(directives):
        raise LegacySyncHardeningError("legacy sync hardening contract is invalid")
    expected = dict(EXPECTED_EFFECTIVE_PROPERTIES)
    if directives != expected:
        raise LegacySyncHardeningError("legacy sync hardening contract is invalid")


def ensure_dropin_directory(paths):
    require_trusted_unit_directories(paths)
    try:
        metadata = paths.dropin_directory.lstat()
    except FileNotFoundError:
        try:
            paths.dropin_directory.mkdir(mode=0o755)
            os.chmod(paths.dropin_directory, 0o755)
            fsync_directory(paths.dropin_directory.parent)
        except OSError as error:
            raise LegacySyncHardeningError("legacy sync hardening directory could not be created") from error
        _require_trusted_directory(
            paths.dropin_directory, paths.expected_uid, paths.expected_gid
        )
        return True
    except OSError as error:
        raise LegacySyncHardeningError("legacy sync hardening directory is unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode) or paths.dropin_directory.is_symlink():
        raise LegacySyncHardeningError("legacy sync hardening directory is unsafe")
    _require_trusted_directory(paths.dropin_directory, paths.expected_uid, paths.expected_gid)
    return False


def fsync_directory(directory):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def remove_file_if_identity(path, identity):
    try:
        metadata = pathlib.Path(path).lstat()
        if not stat.S_ISREG(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != identity:
            return False
        pathlib.Path(path).unlink()
        return True
    except OSError:
        return False


def inspect_dropin(paths, *, missing_ok=False):
    try:
        payload, snapshot = read_trusted_regular_file(
            paths.dropin_path,
            expected_uid=paths.expected_uid,
            expected_gid=paths.expected_gid,
            expected_mode=0o644,
            maximum_bytes=len(HARDENING_DROPIN),
        )
    except LegacySyncHardeningError as error:
        try:
            missing = not paths.dropin_path.exists() and not paths.dropin_path.is_symlink()
        except OSError:
            missing = False
        if missing_ok and missing:
            return None
        raise error
    if payload != HARDENING_DROPIN:
        raise LegacySyncHardeningError("legacy sync hardening drop-in is unsafe")
    return snapshot


def write_dropin(paths):
    existing = inspect_dropin(paths, missing_ok=True)
    if existing is not None:
        return False, existing
    temporary = paths.dropin_directory / ("." + paths.dropin_path.name + ".tmp-" + secrets.token_hex(16))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, 0o644)
        os.fchmod(descriptor, 0o644)
        written = 0
        while written < len(HARDENING_DROPIN):
            written += os.write(descriptor, HARDENING_DROPIN[written:])
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        temporary_identity = (metadata.st_dev, metadata.st_ino)
    except OSError as error:
        raise LegacySyncHardeningError("legacy sync hardening drop-in could not be written") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)

    linked = False
    try:
        os.link(temporary, paths.dropin_path, follow_symlinks=False)
        linked = True
    except FileExistsError:
        try:
            temporary.unlink()
        except OSError:
            pass
        existing = inspect_dropin(paths, missing_ok=False)
        return False, existing
    except OSError as error:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise LegacySyncHardeningError("legacy sync hardening drop-in could not be installed") from error
    try:
        temporary.unlink()
    except OSError as error:
        # The final name is a second link until the temporary name is removed.
        # Remove it before returning so systemd never sees an unverified file.
        if linked:
            remove_file_if_identity(paths.dropin_path, temporary_identity)
        raise LegacySyncHardeningError("legacy sync hardening drop-in could not be finalized") from error
    try:
        snapshot = inspect_dropin(paths, missing_ok=False)
    except LegacySyncHardeningError:
        remove_file_if_identity(paths.dropin_path, temporary_identity)
        raise
    try:
        fsync_directory(paths.dropin_directory)
    except OSError as error:
        # The caller has a verified identity and can remove this exact file.
        raise DropinFinalizationError(snapshot) from error
    return True, snapshot


def remove_created_dropin(paths, expected_snapshot):
    actual = inspect_dropin(paths, missing_ok=False)
    if actual != expected_snapshot:
        raise LegacySyncHardeningError("legacy sync hardening drop-in changed during recovery")
    try:
        paths.dropin_path.unlink()
        fsync_directory(paths.dropin_directory)
    except OSError as error:
        raise LegacySyncHardeningError("legacy sync hardening drop-in could not be removed") from error


def remove_created_directory(paths):
    try:
        _require_trusted_directory(paths.dropin_directory, paths.expected_uid, paths.expected_gid)
        paths.dropin_directory.rmdir()
        fsync_directory(paths.dropin_directory.parent)
    except (OSError, LegacySyncHardeningError):
        # An empty root-owned drop-in directory has no systemd configuration
        # effect.  Do not remove a directory if another root operation used it.
        return


def verify_unit_snapshot_unchanged(paths, expected_snapshot):
    _payload, actual = read_unit_fragment(paths)
    if actual != expected_snapshot:
        raise LegacySyncHardeningError("legacy sync unit changed during hardening")


def _read_proc_text(path, maximum_bytes):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LegacySyncHardeningError("legacy sync listener metadata is unavailable") from error
    try:
        payload = os.read(descriptor, maximum_bytes + 1)
        if len(payload) > maximum_bytes:
            raise LegacySyncHardeningError("legacy sync listener metadata is invalid")
    finally:
        os.close(descriptor)
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise LegacySyncHardeningError("legacy sync listener metadata is invalid") from error


def _decode_listener_address(value, family):
    host, separator, port_hex = value.partition(":")
    if (
        not separator
        or not re.fullmatch(r"[0-9A-Fa-f]{4}", port_hex)
        or (family == TCP4_FAMILY and not re.fullmatch(r"[0-9A-Fa-f]{8}", host))
        or (family == TCP6_FAMILY and not re.fullmatch(r"[0-9A-Fa-f]{32}", host))
    ):
        raise LegacySyncHardeningError("legacy sync listener metadata is invalid")
    raw = bytes.fromhex(host)
    if family == TCP4_FAMILY:
        address = ipaddress.IPv4Address(raw[::-1])
    else:
        address = ipaddress.IPv6Address(b"".join(
            raw[index:index + 4][::-1] for index in range(0, len(raw), 4)
        ))
    return address, int(port_hex, 16)
def read_tcp_listeners(proc_root):
    listeners = []
    for name, family in (("tcp", TCP4_FAMILY), ("tcp6", TCP6_FAMILY)):
        path = pathlib.Path(proc_root) / "net" / name
        try:
            payload = _read_proc_text(path, 1024 * 1024)
        except LegacySyncHardeningError:
            if name == "tcp6" and not path.exists():
                continue
            raise
        lines = payload.splitlines()
        if not lines:
            raise LegacySyncHardeningError("legacy sync listener metadata is invalid")
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 10:
                raise LegacySyncHardeningError("legacy sync listener metadata is invalid")
            if fields[3] != "0A":
                continue
            address, port = _decode_listener_address(fields[1], family)
            if not fields[9].isdigit():
                raise LegacySyncHardeningError("legacy sync listener metadata is invalid")
            listeners.append((address, port, int(fields[9])))
    return listeners


def process_socket_inodes(proc_root, pid):
    directory = pathlib.Path(proc_root) / str(pid) / "fd"
    try:
        entries = list(directory.iterdir())
    except OSError as error:
        raise LegacySyncHardeningError("legacy sync process metadata is unavailable") from error
    inodes = set()
    for entry in entries:
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[([0-9]+)\]", target)
        if match:
            inodes.add(int(match.group(1)))
    if not inodes:
        raise LegacySyncHardeningError("legacy sync process socket metadata is unavailable")
    return inodes


def verify_loopback_listener(pid, *, proc_root=pathlib.Path("/proc")):
    all_listeners = [
        (address, port)
        for address, port, inode in read_tcp_listeners(proc_root)
        if port == SYNC_PORT
    ]
    if any(not address.is_loopback for address, _port in all_listeners):
        raise LegacySyncHardeningError("legacy sync listener is not loopback-only")
    owned = process_socket_inodes(proc_root, pid)
    if not any(
        inode in owned and port == SYNC_PORT
        for _address, port, inode in read_tcp_listeners(proc_root)
    ):
        raise LegacySyncHardeningError("legacy sync listener is not loopback-only")


def probe_loopback_health():
    connection = http.client.HTTPConnection("127.0.0.1", SYNC_PORT, timeout=4)
    try:
        connection.request("GET", "/healthz", headers={"Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            raise LegacySyncHardeningError("legacy sync loopback health check failed")
        if len(response.read(MAX_HEALTH_RESPONSE_BYTES + 1)) > MAX_HEALTH_RESPONSE_BYTES:
            raise LegacySyncHardeningError("legacy sync loopback health response is invalid")
    except (OSError, http.client.HTTPException) as error:
        raise LegacySyncHardeningError("legacy sync loopback health check failed") from error
    finally:
        connection.close()


def verify_effective_hardening(*, runner=run_command):
    values = systemctl_properties(runner, tuple(EXPECTED_EFFECTIVE_PROPERTIES))
    if values != EXPECTED_EFFECTIVE_PROPERTIES:
        raise LegacySyncHardeningError("legacy sync sandbox settings are not effective")


def verify_legacy_runtime(paths, *, runner=run_command, health_probe=probe_loopback_health, listener_verifier=verify_loopback_listener):
    unit = inspect_active_unit(paths, runner=runner)
    listener_verifier(unit.main_pid, proc_root=paths.proc_root)
    health_probe()
    return unit


def wait_for_runtime(
    paths,
    *,
    require_hardening,
    runner=run_command,
    health_probe=probe_loopback_health,
    listener_verifier=verify_loopback_listener,
    clock=time.monotonic,
    sleeper=time.sleep,
):
    deadline = clock() + HEALTH_TIMEOUT_SECONDS
    while True:
        try:
            unit = verify_legacy_runtime(
                paths,
                runner=runner,
                health_probe=health_probe,
                listener_verifier=listener_verifier,
            )
            if require_hardening:
                verify_effective_hardening(runner=runner)
            return unit
        except LegacySyncHardeningError:
            if clock() >= deadline:
                if require_hardening:
                    raise LegacySyncHardeningError("legacy sync hardening verification failed")
                raise LegacySyncHardeningError("legacy sync service did not recover")
            sleeper(1)


def systemctl_daemon_reload(*, runner=run_command):
    invoke(runner, [SYSTEMCTL, "daemon-reload"], timeout=COMMAND_TIMEOUT_SECONDS)


def systemctl_restart(paths, expected_snapshot, *, runner=run_command):
    validate_restart_contract(paths, expected_snapshot, runner=runner)
    invoke(runner, [SYSTEMCTL, "restart", UNIT_NAME], timeout=RESTART_TIMEOUT_SECONDS)


def rollback_original_service(
    paths,
    *,
    unit_snapshot,
    dropin_snapshot,
    directory_created,
    runner=run_command,
    health_probe=probe_loopback_health,
    listener_verifier=verify_loopback_listener,
    clock=time.monotonic,
    sleeper=time.sleep,
):
    try:
        remove_created_dropin(paths, dropin_snapshot)
        systemctl_daemon_reload(runner=runner)
        systemctl_restart(paths, unit_snapshot, runner=runner)
        wait_for_runtime(
            paths,
            require_hardening=False,
            runner=runner,
            health_probe=health_probe,
            listener_verifier=listener_verifier,
            clock=clock,
            sleeper=sleeper,
        )
    except BaseException:
        return False
    if directory_created:
        remove_created_directory(paths)
    return True


@contextlib.contextmanager
def interruption_guard():
    previous = {}

    def interrupted(_signum, _frame):
        raise OperationInterrupted("legacy sync hardening was interrupted")

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupted)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def apply_hardening(
    paths,
    *,
    runner=run_command,
    health_probe=probe_loopback_health,
    listener_verifier=verify_loopback_listener,
    clock=time.monotonic,
    sleeper=time.sleep,
):
    validate_dropin_contract()
    original = wait_for_runtime(
        paths,
        require_hardening=False,
        runner=runner,
        health_probe=health_probe,
        listener_verifier=listener_verifier,
        clock=clock,
        sleeper=sleeper,
    )
    directory_created = ensure_dropin_directory(paths)
    created_dropin = False
    dropin_snapshot = None
    with interruption_guard():
        try:
            try:
                created_dropin, dropin_snapshot = write_dropin(paths)
            except DropinFinalizationError as error:
                created_dropin = True
                dropin_snapshot = error.snapshot
                raise
            if not created_dropin:
                wait_for_runtime(
                    paths,
                    require_hardening=True,
                    runner=runner,
                    health_probe=health_probe,
                    listener_verifier=listener_verifier,
                    clock=clock,
                    sleeper=sleeper,
                )
                return False
            systemctl_daemon_reload(runner=runner)
            systemctl_restart(paths, original.fragment_snapshot, runner=runner)
            wait_for_runtime(
                paths,
                require_hardening=True,
                runner=runner,
                health_probe=health_probe,
                listener_verifier=listener_verifier,
                clock=clock,
                sleeper=sleeper,
            )
            return True
        except BaseException:
            if created_dropin and rollback_original_service(
                paths,
                unit_snapshot=original.fragment_snapshot,
                dropin_snapshot=dropin_snapshot,
                directory_created=directory_created,
                runner=runner,
                health_probe=health_probe,
                listener_verifier=listener_verifier,
                clock=clock,
                sleeper=sleeper,
            ):
                raise LegacySyncHardeningError(
                    "legacy sync hardening failed; original service configuration was restored"
                ) from None
            if directory_created and not created_dropin:
                remove_created_directory(paths)
            raise LegacySyncHardeningError("legacy sync hardening verification failed") from None


def require_safe_system_binary(path):
    try:
        metadata = pathlib.Path(path).lstat()
    except OSError as error:
        raise LegacySyncHardeningError("required system service command is unavailable") from error
    if (
        not pathlib.Path(path).is_absolute()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not metadata.st_mode & stat.S_IXUSR
        or pathlib.Path(path).is_symlink()
    ):
        raise LegacySyncHardeningError("required system service command is unsafe")


def require_trusted_release_path(
    path, *, expects_directory, expected_uid=0, expected_gid=0
):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise LegacySyncHardeningError("trusted legacy sync release path is unavailable") from error
    if (
        not target.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or (expects_directory and not stat.S_ISDIR(metadata.st_mode))
        or (not expects_directory and not stat.S_ISREG(metadata.st_mode))
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise LegacySyncHardeningError("trusted legacy sync release path is unsafe")


def require_trusted_release_tree(
    paths, *, source_path=None, expected_uid=0, expected_gid=0
):
    trusted_root = pathlib.Path(TRUSTED_RELEASE_ROOT)
    if (
        pathlib.Path(paths.repo_dir) != trusted_root
        or pathlib.Path(paths.trusted_release_root) != trusted_root
        or trusted_root.parent != TRUSTED_RELEASE_PARENT
        or trusted_root.parent.parent != TRUSTED_FILESYSTEM_ROOT
    ):
        raise LegacySyncHardeningError(
            "legacy sync hardening must run from the trusted production release tree"
        )
    expected_guard = trusted_root / CLEAN_WORKTREE_RELATIVE_PATH
    if pathlib.Path(paths.clean_worktree) != expected_guard:
        raise LegacySyncHardeningError(
            "legacy sync clean worktree guard is outside the trusted release tree"
        )
    try:
        resolved_source = (
            pathlib.Path(__file__).resolve(strict=True)
            if source_path is None
            else pathlib.Path(source_path).resolve(strict=True)
        )
    except OSError as error:
        raise LegacySyncHardeningError("trusted legacy sync controller source is unavailable") from error
    expected_source = trusted_root / CONTROLLER_SOURCE_RELATIVE_PATH
    if resolved_source != expected_source:
        raise LegacySyncHardeningError(
            "legacy sync hardening controller is outside the trusted release tree"
        )
    for path, expects_directory in (
        (TRUSTED_FILESYSTEM_ROOT, True),
        (TRUSTED_RELEASE_PARENT, True),
        (trusted_root, True),
        (trusted_root / "deploy", True),
        (expected_source, False),
        (expected_guard, False),
    ):
        require_trusted_release_path(
            path,
            expects_directory=expects_directory,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )


def require_production_apply_context(paths, streams=(sys.stdin, sys.stdout, sys.stderr)):
    if os.geteuid() != 0 or paths.repo_dir != paths.trusted_release_root:
        raise LegacySyncHardeningError(
            "legacy sync hardening requires root from the trusted production release tree"
        )
    try:
        private_tty = all(stream.isatty() for stream in streams)
    except (AttributeError, OSError, ValueError):
        private_tty = False
    if not private_tty:
        raise LegacySyncHardeningError("legacy sync hardening requires a private interactive TTY")
    require_trusted_release_tree(paths)
    for executable in (SYSTEMCTL, BASH, EXPECTED_PYTHON):
        require_safe_system_binary(executable)


def require_clean_worktree(paths, *, runner=run_command):
    invoke(
        runner,
        [BASH, str(paths.clean_worktree), "check"],
        timeout=COMMAND_TIMEOUT_SECONDS,
    )


def verify_hardened_service(
    paths,
    *,
    runner=run_command,
    health_probe=probe_loopback_health,
    listener_verifier=verify_loopback_listener,
):
    validate_dropin_contract()
    require_trusted_unit_directories(paths)
    inspect_dropin(paths, missing_ok=False)
    verify_legacy_runtime(
        paths,
        runner=runner,
        health_probe=health_probe,
        listener_verifier=listener_verifier,
    )
    verify_effective_hardening(runner=runner)


def emit(event, *, stream=sys.stdout, **metadata):
    fields = {"event": event, **metadata}
    encoded = "{" + ",".join(
        f'"{key}":{json_value(value)}' for key, value in sorted(fields.items())
    ) + "}"
    print(encoded, file=stream, flush=True)


def json_value(value):
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    raise LegacySyncHardeningError("legacy sync hardening output is invalid")


def main(argv=None):
    parser = RedactedArgumentParser(description="Harden the fixed legacy sync systemd service")
    parser.add_argument("mode", nargs="?", choices=("check", "verify"), default="check")
    parser.add_argument("--apply", action="store_true")
    try:
        arguments = parser.parse_args(argv)
        if arguments.apply and arguments.mode != "check":
            raise LegacySyncHardeningError("legacy sync hardening command validation failed")
        paths = production_paths()
        validate_dropin_contract()
        if arguments.apply:
            require_production_apply_context(paths)
            require_clean_worktree(paths)
            changed = apply_hardening(paths)
            emit(
                "legacy_sync_hardening_applied",
                changed=changed,
                sandbox_directives=len(EXPECTED_EFFECTIVE_PROPERTIES),
            )
            return 0
        if arguments.mode == "verify":
            if os.geteuid() != 0:
                raise LegacySyncHardeningError("legacy sync hardening verification requires root")
            require_safe_system_binary(SYSTEMCTL)
            verify_hardened_service(paths)
            emit(
                "legacy_sync_hardening_verified",
                sandbox_directives=len(EXPECTED_EFFECTIVE_PROPERTIES),
            )
            return 0
        emit(
            "legacy_sync_hardening_contract_verified",
            sandbox_directives=len(EXPECTED_EFFECTIVE_PROPERTIES),
        )
        return 0
    except (LegacySyncHardeningError, KeyboardInterrupt):
        emit("legacy_sync_hardening_failed", stream=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
