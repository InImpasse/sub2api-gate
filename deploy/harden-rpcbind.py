#!/usr/bin/python3 -I
"""Safely disable an unused local rpcbind service and socket.

The controller intentionally has a narrow mutation boundary: it only invokes
``systemctl`` for ``rpcbind.service`` and ``rpcbind.socket``.  Before either
unit is disabled, it proves that the current mount namespace has no NFS
mounts, that local RPC registration contains no program other than portmapper,
and that no other systemd unit depends on either target.  A root-only state
record permits an explicit restore and is used to recover automatically from a
failed apply.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import pathlib
import re
import secrets
import signal
import stat
import subprocess
import sys


REPO_DIR = pathlib.Path(__file__).resolve().parents[1]
TRUSTED_FILESYSTEM_ROOT = pathlib.Path("/")
TRUSTED_RELEASE_PARENT = pathlib.Path("/opt")
TRUSTED_RELEASE_ROOT = TRUSTED_RELEASE_PARENT / "sub2api-gate-release"
CONTROLLER_SOURCE_RELATIVE_PATH = pathlib.Path("deploy/harden-rpcbind.py")
CLEAN_WORKTREE_RELATIVE_PATH = pathlib.Path("deploy/require-clean-worktree.sh")
CLEAN_WORKTREE = TRUSTED_RELEASE_ROOT / CLEAN_WORKTREE_RELATIVE_PATH
SYSTEMCTL = "/usr/bin/systemctl"
RPCINFO = "/usr/sbin/rpcinfo"
BASH = "/bin/bash"
STATE_ROOT = pathlib.Path("/run/sub2api-gate")
STATE_PATH = STATE_ROOT / "rpcbind-hardening-state.json"
PROC_ROOT = pathlib.Path("/proc")
MOUNTINFO_PATH = PROC_ROOT / "self" / "mountinfo"
TARGET_UNITS = ("rpcbind.service", "rpcbind.socket")
PORTMAPPER_PROGRAM = 100000
RPCBIND_PORT = 111
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
STATE_VERSION = 2
MAX_HOST_INPUT_BYTES = 1024 * 1024
MAX_STATE_BYTES = 4096
COMMAND_TIMEOUT_SECONDS = 30
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENABLED_STATES = frozenset({"enabled", "enabled-runtime"})
DISABLED_STATES = frozenset({"disabled", "disabled-runtime", "static", "indirect"})
SUPPORTED_ENABLED_STATES = ENABLED_STATES | DISABLED_STATES
SUPPORTED_ACTIVE_STATES = frozenset({"active", "inactive"})
RPCINFO_HEADER = ("program", "vers", "proto", "port", "service")
RPCINFO_RECORD = re.compile(r"([0-9]+)\s+([0-9]+)\s+(tcp|udp|tcp6|udp6)\s+([0-9]+)\s+(\S+)")
SYSTEMD_UNIT_NAME = re.compile(
    r"(?:[A-Za-z0-9_.@:-]|\\x[0-9A-Fa-f]{2})+"
    r"\.(?:service|socket|target|mount|automount|path|timer|slice|scope|device|swap|busname)"
)


class RpcbindHardeningError(RuntimeError):
    pass


class OperationInterrupted(RpcbindHardeningError):
    pass


class RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise RpcbindHardeningError("rpcbind hardening command validation failed")


@dataclasses.dataclass(frozen=True)
class HardeningPaths:
    repo_dir: pathlib.Path
    trusted_release_root: pathlib.Path
    clean_worktree: pathlib.Path
    state_root: pathlib.Path
    state_path: pathlib.Path
    proc_root: pathlib.Path
    mountinfo_path: pathlib.Path
    expected_uid: int = 0
    expected_gid: int = 0


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes = b""


@dataclasses.dataclass(frozen=True)
class UnitState:
    enabled: str
    active: str


@dataclasses.dataclass(frozen=True)
class RpcbindState:
    service: UnitState
    socket: UnitState

    def for_unit(self, unit):
        if unit == TARGET_UNITS[0]:
            return self.service
        if unit == TARGET_UNITS[1]:
            return self.socket
        raise RpcbindHardeningError("rpcbind target unit is invalid")


@dataclasses.dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    size: int


def production_paths():
    return HardeningPaths(
        repo_dir=REPO_DIR,
        trusted_release_root=TRUSTED_RELEASE_ROOT,
        clean_worktree=CLEAN_WORKTREE,
        state_root=STATE_ROOT,
        state_path=STATE_PATH,
        proc_root=PROC_ROOT,
        mountinfo_path=MOUNTINFO_PATH,
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
        raise RpcbindHardeningError("required local rpcbind command failed") from error
    stdout = result.stdout if isinstance(result.stdout, bytes) else b""
    return CommandResult(result.returncode, stdout)


def invoke(runner, command, *, timeout=COMMAND_TIMEOUT_SECONDS, allow_failure=False):
    try:
        result = runner(command, timeout=timeout)
    except RpcbindHardeningError:
        raise
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RpcbindHardeningError("required local rpcbind command failed") from error
    stdout = getattr(result, "stdout", b"")
    if isinstance(stdout, str):
        stdout = stdout.encode("utf-8", "replace")
    returncode = getattr(result, "returncode", None)
    if (
        not isinstance(stdout, bytes)
        or len(stdout) > MAX_COMMAND_OUTPUT_BYTES
        or not isinstance(returncode, int)
    ):
        raise RpcbindHardeningError("local rpcbind command result is invalid")
    if returncode != 0 and not allow_failure:
        raise RpcbindHardeningError("required local rpcbind command failed")
    return CommandResult(returncode, stdout)


def require_safe_system_binary(path):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise RpcbindHardeningError("required system rpcbind command is unavailable") from error
    if (
        not target.is_absolute()
        or target.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not metadata.st_mode & stat.S_IXUSR
    ):
        raise RpcbindHardeningError("required system rpcbind command is unsafe")


def require_trusted_release_path(
    path, *, expects_directory, expected_uid=0, expected_gid=0
):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise RpcbindHardeningError("trusted rpcbind release path is unavailable") from error
    if (
        not target.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or (expects_directory and not stat.S_ISDIR(metadata.st_mode))
        or (not expects_directory and not stat.S_ISREG(metadata.st_mode))
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RpcbindHardeningError("trusted rpcbind release path has an unsafe identity")


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
        raise RpcbindHardeningError(
            "rpcbind hardening must run from the trusted production release tree"
        )
    expected_guard = trusted_root / CLEAN_WORKTREE_RELATIVE_PATH
    if pathlib.Path(paths.clean_worktree) != expected_guard:
        raise RpcbindHardeningError(
            "rpcbind clean worktree guard is outside the trusted release tree"
        )
    try:
        source_path = (
            pathlib.Path(__file__).resolve(strict=True)
            if source_path is None
            else pathlib.Path(source_path).resolve(strict=True)
        )
    except OSError as error:
        raise RpcbindHardeningError("trusted rpcbind controller source is unavailable") from error
    expected_source = trusted_root / CONTROLLER_SOURCE_RELATIVE_PATH
    if source_path != expected_source:
        raise RpcbindHardeningError(
            "rpcbind controller source is outside the trusted release tree"
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
        raise RpcbindHardeningError(
            "rpcbind hardening requires root from the trusted production release tree"
        )
    if not all(stream.isatty() for stream in streams):
        raise RpcbindHardeningError("rpcbind hardening requires a private interactive TTY")
    require_trusted_release_tree(paths)
    for executable in (SYSTEMCTL, RPCINFO, BASH):
        require_safe_system_binary(executable)


def require_clean_worktree(paths, *, runner=run_command):
    invoke(
        runner,
        [BASH, str(paths.clean_worktree), "check"],
        timeout=COMMAND_TIMEOUT_SECONDS,
    )


def validate_contract(paths):
    if (
        TARGET_UNITS != ("rpcbind.service", "rpcbind.socket")
        or RPCBIND_PORT != 111
        or PORTMAPPER_PROGRAM != 100000
        or paths.state_path.parent != paths.state_root
        or not paths.state_root.is_absolute()
        or paths.state_root == pathlib.Path("/")
    ):
        raise RpcbindHardeningError("rpcbind hardening contract is invalid")


def _directory_metadata(path, *, expected_uid, expected_gid, private):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise RpcbindHardeningError("rpcbind hardening state directory is unavailable") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        target.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or mode & 0o022
        or (private and mode & 0o077)
    ):
        raise RpcbindHardeningError("rpcbind hardening state directory is unsafe")
    return metadata


def fsync_directory(path):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_state_directory(paths):
    _directory_metadata(
        paths.state_root.parent,
        expected_uid=paths.expected_uid,
        expected_gid=paths.expected_gid,
        private=False,
    )
    try:
        metadata = paths.state_root.lstat()
    except FileNotFoundError:
        try:
            paths.state_root.mkdir(mode=0o700)
            os.chmod(paths.state_root, 0o700)
            fsync_directory(paths.state_root.parent)
        except OSError as error:
            raise RpcbindHardeningError("rpcbind hardening state directory could not be created") from error
    except OSError as error:
        raise RpcbindHardeningError("rpcbind hardening state directory is unavailable") from error
    else:
        if paths.state_root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise RpcbindHardeningError("rpcbind hardening state directory is unsafe")
    _directory_metadata(
        paths.state_root,
        expected_uid=paths.expected_uid,
        expected_gid=paths.expected_gid,
        private=True,
    )


def _file_identity(metadata):
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        mode=stat.S_IMODE(metadata.st_mode),
        size=metadata.st_size,
    )


def _validate_state_file(paths):
    try:
        metadata = paths.state_path.lstat()
    except OSError as error:
        raise RpcbindHardeningError("rpcbind hardening state is unavailable") from error
    if (
        paths.state_path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != paths.expected_uid
        or metadata.st_gid != paths.expected_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_STATE_BYTES
    ):
        raise RpcbindHardeningError("rpcbind hardening state is unsafe")
    return _file_identity(metadata)


def _write_all(descriptor, payload):
    offset = 0
    while offset < len(payload):
        offset += os.write(descriptor, payload[offset:])


def _state_payload(state, port_bound):
    if not isinstance(port_bound, bool):
        raise RpcbindHardeningError("rpcbind hardening state is invalid")
    document = {
        "service": {"active": state.service.active, "enabled": state.service.enabled},
        "socket": {"active": state.socket.active, "enabled": state.socket.enabled},
        "port_bound": port_bound,
        "version": STATE_VERSION,
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _validate_unit_state(value):
    if (
        not isinstance(value, UnitState)
        or value.enabled not in SUPPORTED_ENABLED_STATES
        or value.active not in SUPPORTED_ACTIVE_STATES
    ):
        raise RpcbindHardeningError("rpcbind unit state is not safely reversible")


def _parse_state(payload):
    try:
        document = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RpcbindHardeningError("rpcbind hardening state is invalid") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "service", "socket", "port_bound"}
        or document["version"] != STATE_VERSION
        or not isinstance(document["port_bound"], bool)
    ):
        raise RpcbindHardeningError("rpcbind hardening state is invalid")
    units = []
    for name in ("service", "socket"):
        value = document[name]
        if not isinstance(value, dict) or set(value) != {"enabled", "active"}:
            raise RpcbindHardeningError("rpcbind hardening state is invalid")
        unit = UnitState(value["enabled"], value["active"])
        _validate_unit_state(unit)
        units.append(unit)
    return RpcbindState(service=units[0], socket=units[1]), document["port_bound"]


def state_exists(paths):
    try:
        paths.state_path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise RpcbindHardeningError("rpcbind hardening state is unavailable") from error
    return True


def write_state(paths, state, port_bound):
    _validate_unit_state(state.service)
    _validate_unit_state(state.socket)
    ensure_state_directory(paths)
    if state_exists(paths):
        raise RpcbindHardeningError("existing rpcbind hardening state requires restore or verification")
    payload = _state_payload(state, port_bound)
    if len(payload) > MAX_STATE_BYTES:
        raise RpcbindHardeningError("rpcbind hardening state is invalid")
    temporary = paths.state_root / ("." + paths.state_path.name + ".tmp-" + secrets.token_hex(16))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        os.fchown(descriptor, paths.expected_uid, paths.expected_gid)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        temporary_identity = _file_identity(os.fstat(descriptor))
    except OSError as error:
        raise RpcbindHardeningError("rpcbind hardening state could not be written") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        os.link(temporary, paths.state_path, follow_symlinks=False)
    except FileExistsError as error:
        raise RpcbindHardeningError("existing rpcbind hardening state requires restore or verification") from error
    except OSError as error:
        raise RpcbindHardeningError("rpcbind hardening state could not be installed") from error
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
    try:
        identity = _validate_state_file(paths)
        if identity != temporary_identity:
            raise RpcbindHardeningError("rpcbind hardening state changed while being installed")
        fsync_directory(paths.state_root)
    except BaseException:
        try:
            actual = _validate_state_file(paths)
            if actual == temporary_identity:
                paths.state_path.unlink()
                fsync_directory(paths.state_root)
        except BaseException:
            pass
        raise
    return identity


def read_state(paths):
    ensure_state_directory(paths)
    expected = _validate_state_file(paths)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(paths.state_path, flags)
    except OSError as error:
        raise RpcbindHardeningError("rpcbind hardening state is unavailable") from error
    try:
        opened = _file_identity(os.fstat(descriptor))
        if opened != expected:
            raise RpcbindHardeningError("rpcbind hardening state changed while being read")
        payload = os.read(descriptor, MAX_STATE_BYTES + 1)
        if len(payload) > MAX_STATE_BYTES:
            raise RpcbindHardeningError("rpcbind hardening state is invalid")
    except OSError as error:
        raise RpcbindHardeningError("rpcbind hardening state could not be read") from error
    finally:
        os.close(descriptor)
    state, port_bound = _parse_state(payload)
    return state, port_bound, expected


def remove_state(paths, expected_identity):
    actual = _validate_state_file(paths)
    if actual != expected_identity:
        raise RpcbindHardeningError("rpcbind hardening state changed during recovery")
    try:
        paths.state_path.unlink()
        fsync_directory(paths.state_root)
    except OSError as error:
        raise RpcbindHardeningError("rpcbind hardening state could not be removed") from error


def _read_limited_text(path, maximum_bytes, label):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RpcbindHardeningError(f"{label} is unavailable") from error
    try:
        chunks = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    except OSError as error:
        raise RpcbindHardeningError(f"{label} could not be read") from error
    finally:
        os.close(descriptor)
    if len(payload) > maximum_bytes:
        raise RpcbindHardeningError(f"{label} is too large")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RpcbindHardeningError(f"{label} is invalid") from error


def verify_no_nfs_mounts(paths):
    payload = _read_limited_text(paths.mountinfo_path, MAX_HOST_INPUT_BYTES, "mount metadata")
    for line in payload.splitlines():
        if not line:
            continue
        _left, separator, right = line.partition(" - ")
        fields = right.split()
        if not separator or not fields:
            raise RpcbindHardeningError("mount metadata is invalid")
        if fields[0] in {"nfs", "nfs4"}:
            raise RpcbindHardeningError("NFS mounts prevent rpcbind hardening")


def port_111_is_bound(paths):
    for name in ("tcp", "tcp6", "udp", "udp6"):
        path = paths.proc_root / "net" / name
        try:
            payload = _read_limited_text(path, MAX_HOST_INPUT_BYTES, "socket metadata")
        except RpcbindHardeningError:
            if not path.exists():
                continue
            raise
        lines = payload.splitlines()
        if not lines:
            raise RpcbindHardeningError("socket metadata is invalid")
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 4:
                raise RpcbindHardeningError("socket metadata is invalid")
            _host, separator, port = fields[1].partition(":")
            if not separator or not re.fullmatch(r"[0-9A-Fa-f]{4}", port):
                raise RpcbindHardeningError("socket metadata is invalid")
            if int(port, 16) == RPCBIND_PORT:
                return True
    return False


def verify_port_111_absent(paths, *, port_inspector=port_111_is_bound):
    if port_inspector(paths):
        raise RpcbindHardeningError("rpcbind port 111 remains bound")


def verify_recorded_port_state(paths, expected_port_bound, *, port_inspector=port_111_is_bound):
    observed = port_inspector(paths)
    if (
        not isinstance(expected_port_bound, bool)
        or not isinstance(observed, bool)
        or observed != expected_port_bound
    ):
        raise RpcbindHardeningError("rpcbind prior listener state could not be restored")



def _command_text(result, label):
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RpcbindHardeningError(f"{label} output is invalid") from error


def _single_status(result, label, allowed):
    # systemctl is-active reports an inactive unit with status 3, while
    # is-enabled commonly uses 1 for disabled units.  The text is still
    # validated against a closed set below.
    if result.returncode not in {0, 1, 3}:
        raise RpcbindHardeningError(f"{label} output is invalid")
    text = _command_text(result, label)
    lines = text.splitlines()
    if len(lines) != 1 or lines[0] != lines[0].strip() or lines[0] not in allowed:
        raise RpcbindHardeningError(f"{label} output is invalid")
    return lines[0]


def _parse_properties(result, expected):
    text = _command_text(result, "systemd unit state")
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in expected or key in values:
            raise RpcbindHardeningError("systemd unit state is invalid")
        values[key] = value
    if set(values) != set(expected):
        raise RpcbindHardeningError("systemd unit state is invalid")
    return values


def require_loaded_unit(unit, *, runner=run_command):
    result = invoke(
        runner,
        [SYSTEMCTL, "show", unit, "--property=Id", "--property=LoadState"],
    )
    values = _parse_properties(result, ("Id", "LoadState"))
    if values != {"Id": unit, "LoadState": "loaded"}:
        raise RpcbindHardeningError("rpcbind unit is unavailable")


def read_unit_state(unit, *, runner=run_command):
    require_loaded_unit(unit, runner=runner)
    enabled = _single_status(
        invoke(runner, [SYSTEMCTL, "is-enabled", unit], allow_failure=True),
        "systemd enable state",
        SUPPORTED_ENABLED_STATES,
    )
    active = _single_status(
        invoke(runner, [SYSTEMCTL, "is-active", unit], allow_failure=True),
        "systemd active state",
        SUPPORTED_ACTIVE_STATES,
    )
    state = UnitState(enabled=enabled, active=active)
    _validate_unit_state(state)
    return state


def read_rpcbind_state(*, runner=run_command):
    return RpcbindState(
        service=read_unit_state(TARGET_UNITS[0], runner=runner),
        socket=read_unit_state(TARGET_UNITS[1], runner=runner),
    )


def verify_reverse_service_dependencies(unit, *, runner=run_command):
    result = invoke(
        runner,
        [SYSTEMCTL, "list-dependencies", "--reverse", "--all", "--plain", "--no-pager", unit],
    )
    text = _command_text(result, "systemd dependency")
    dependencies = set()
    for raw_line in text.splitlines():
        if not raw_line:
            continue
        if raw_line != raw_line.strip() or SYSTEMD_UNIT_NAME.fullmatch(raw_line) is None:
            raise RpcbindHardeningError("systemd dependency output is invalid")
        dependencies.add(raw_line)
    if unit not in dependencies:
        raise RpcbindHardeningError("systemd dependency output is invalid")
    unexpected = dependencies.difference(TARGET_UNITS)
    if unexpected:
        raise RpcbindHardeningError("reverse systemd dependencies prevent rpcbind hardening")


def verify_rpc_programs(port_bound, *, runner=run_command):
    result = invoke(runner, [RPCINFO, "-p", "127.0.0.1"], allow_failure=True)
    if result.returncode != 0:
        if port_bound:
            raise RpcbindHardeningError("RPC registration could not be verified")
        return
    text = _command_text(result, "RPC registration")
    header_seen = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if not header_seen:
            if tuple(line.lower().split()) != RPCINFO_HEADER:
                raise RpcbindHardeningError("RPC registration output is invalid")
            header_seen = True
            continue
        match = RPCINFO_RECORD.fullmatch(line)
        if match is None:
            raise RpcbindHardeningError("RPC registration output is invalid")
        program, _version, _protocol, port, service = match.groups()
        if int(program) != PORTMAPPER_PROGRAM or int(port) != RPCBIND_PORT or service != "portmapper":
            raise RpcbindHardeningError("registered RPC programs prevent rpcbind hardening")
    if not header_seen:
        raise RpcbindHardeningError("RPC registration output is invalid")


def inspect_safety_evidence(paths, *, runner=run_command, port_inspector=port_111_is_bound):
    verify_no_nfs_mounts(paths)
    state = read_rpcbind_state(runner=runner)
    for unit in TARGET_UNITS:
        verify_reverse_service_dependencies(unit, runner=runner)
    port_bound = port_inspector(paths)
    verify_rpc_programs(port_bound, runner=runner)
    return state, port_bound


def _is_hardened(state, port_bound):
    return (
        all(
            unit.enabled in DISABLED_STATES and unit.active == "inactive"
            for unit in (state.service, state.socket)
        )
        and not port_bound
    )


def disable_and_stop_rpcbind(*, runner=run_command):
    invoke(runner, [SYSTEMCTL, "disable", *TARGET_UNITS])
    invoke(runner, [SYSTEMCTL, "stop", TARGET_UNITS[1], TARGET_UNITS[0]])


def verify_hardened(paths, *, runner=run_command, port_inspector=port_111_is_bound):
    state = read_rpcbind_state(runner=runner)
    verify_port_111_absent(paths, port_inspector=port_inspector)
    if not _is_hardened(state, False):
        raise RpcbindHardeningError("rpcbind service or socket remains enabled or active")
    return state


def _restore_enable_state(unit, previous, *, runner=run_command):
    if previous.enabled == "enabled":
        invoke(runner, [SYSTEMCTL, "enable", unit])
    elif previous.enabled == "enabled-runtime":
        invoke(runner, [SYSTEMCTL, "enable", "--runtime", unit])
    elif previous.enabled == "disabled":
        invoke(runner, [SYSTEMCTL, "disable", unit])
    elif previous.enabled == "disabled-runtime":
        invoke(runner, [SYSTEMCTL, "disable", "--runtime", unit])
    elif previous.enabled not in {"static", "indirect"}:
        raise RpcbindHardeningError("rpcbind unit state is not safely reversible")


def restore_recorded_state(previous, *, runner=run_command):
    for unit in TARGET_UNITS:
        _restore_enable_state(unit, previous.for_unit(unit), runner=runner)
    for unit in TARGET_UNITS:
        if previous.for_unit(unit).active == "active":
            invoke(runner, [SYSTEMCTL, "start", unit])
    for unit in TARGET_UNITS:
        if previous.for_unit(unit).active == "inactive":
            invoke(runner, [SYSTEMCTL, "stop", unit])
    if read_rpcbind_state(runner=runner) != previous:
        raise RpcbindHardeningError("rpcbind prior unit state could not be restored")


@contextlib.contextmanager
def interruption_guard():
    previous = {}

    def interrupted(_signum, _frame):
        raise OperationInterrupted("rpcbind hardening was interrupted")

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupted)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def apply_hardening(paths, *, runner=run_command, port_inspector=port_111_is_bound):
    if state_exists(paths):
        raise RpcbindHardeningError("existing rpcbind hardening state requires restore or verification")
    previous, port_bound = inspect_safety_evidence(
        paths,
        runner=runner,
        port_inspector=port_inspector,
    )
    if _is_hardened(previous, port_bound):
        return False
    state_identity = write_state(paths, previous, port_bound)
    try:
        with interruption_guard():
            disable_and_stop_rpcbind(runner=runner)
            verify_hardened(paths, runner=runner, port_inspector=port_inspector)
    except BaseException:
        try:
            restore_recorded_state(previous, runner=runner)
            verify_recorded_port_state(paths, port_bound, port_inspector=port_inspector)
            remove_state(paths, state_identity)
        except BaseException:
            raise RpcbindHardeningError(
                "rpcbind hardening failed and prior unit state could not be restored"
            ) from None
        raise RpcbindHardeningError("rpcbind hardening failed; prior unit state was restored") from None
    return True


def restore_hardening(paths, *, runner=run_command, port_inspector=port_111_is_bound):
    previous, port_bound, state_identity = read_state(paths)
    current = read_rpcbind_state(runner=runner)
    if not _is_hardened(current, port_inspector(paths)):
        raise RpcbindHardeningError("rpcbind is not in the recorded hardened state")
    try:
        with interruption_guard():
            restore_recorded_state(previous, runner=runner)
            verify_recorded_port_state(paths, port_bound, port_inspector=port_inspector)
    except BaseException:
        try:
            disable_and_stop_rpcbind(runner=runner)
            verify_hardened(paths, runner=runner, port_inspector=port_inspector)
        except BaseException:
            raise RpcbindHardeningError(
                "rpcbind restoration failed and the disabled state could not be confirmed"
            ) from None
        raise RpcbindHardeningError("rpcbind restoration failed; rpcbind remains disabled") from None
    remove_state(paths, state_identity)
    return True


def json_value(value):
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    raise RpcbindHardeningError("rpcbind hardening output is invalid")


def emit(event, *, stream=sys.stdout, **metadata):
    fields = {"event": event, **metadata}
    print(
        "{" + ",".join(f'"{key}":{json_value(value)}' for key, value in sorted(fields.items())) + "}",
        file=stream,
        flush=True,
    )


def main(argv=None):
    parser = RedactedArgumentParser(description="Disable an unused rpcbind service safely")
    parser.add_argument("mode", nargs="?", choices=("check", "verify", "restore"), default="check")
    parser.add_argument("--apply", action="store_true")
    try:
        arguments = parser.parse_args(argv)
        if arguments.apply and arguments.mode == "verify":
            raise RpcbindHardeningError("rpcbind hardening command validation failed")
        if arguments.mode == "restore" and not arguments.apply:
            raise RpcbindHardeningError("rpcbind hardening command validation failed")
        paths = production_paths()
        validate_contract(paths)
        if arguments.apply:
            require_production_apply_context(paths)
            require_clean_worktree(paths)
            if arguments.mode == "restore":
                changed = restore_hardening(paths)
                emit("rpcbind_hardening_restored", changed=changed)
            else:
                changed = apply_hardening(paths)
                emit("rpcbind_hardening_applied", changed=changed)
            return 0
        if arguments.mode == "verify":
            if os.geteuid() != 0:
                raise RpcbindHardeningError("rpcbind hardening verification requires root")
            require_safe_system_binary(SYSTEMCTL)
            verify_hardened(paths)
            emit("rpcbind_hardening_verified", targets=len(TARGET_UNITS))
            return 0
        emit("rpcbind_hardening_contract_verified", targets=len(TARGET_UNITS))
        return 0
    except (RpcbindHardeningError, KeyboardInterrupt):
        emit("rpcbind_hardening_failed", stream=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
