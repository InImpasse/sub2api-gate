#!/usr/bin/python3 -I
"""Prepare and attest the ignored Worker Node.js runtime."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys


TRUSTED_RELEASE_ROOT = pathlib.Path("/opt/sub2api-gate-release")
SOURCE_RELATIVE_PATH = pathlib.Path("deploy/worker-runtime-attestation.py")
RELEASE_GUARD_RELATIVE_PATH = pathlib.Path("deploy/require-clean-worktree.sh")
WORKER_RELATIVE_PATH = pathlib.Path("worker-allow-ip")
PACKAGE_LOCK_RELATIVE_PATH = WORKER_RELATIVE_PATH / "package-lock.json"
NODE_MODULES_RELATIVE_PATH = WORKER_RELATIVE_PATH / "node_modules"
WRANGLER_ENTRY_WITHIN_WORKER = pathlib.Path(
    "node_modules/wrangler/bin/wrangler.js"
)
STATE_DIRECTORY = pathlib.Path("/run/sub2api-gate")
STATE_PATH = STATE_DIRECTORY / "worker-runtime.json"
LOCK_PATH = STATE_DIRECTORY / "worker-runtime.lock"
NODE_BINARY = pathlib.Path("/usr/bin/node")
NPM_BINARY = pathlib.Path("/usr/bin/npm")
GIT_BINARY = pathlib.Path("/usr/bin/git")
WRANGLER_VERSION = "4.112.0"
STATE_VERSION = 1
MAX_STATE_BYTES = 4096
MAX_PACKAGE_LOCK_BYTES = 4 * 1024 * 1024
MAX_RUNTIME_FILES = 100_000
GIT_HEAD_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
NODE_VERSION_RE = re.compile(r"v([0-9]+)\.[0-9]+\.[0-9]+\Z")
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class WorkerRuntimeError(RuntimeError):
    pass


def _stable_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _hash_record(digest, *fields):
    for field in fields:
        value = field if isinstance(field, bytes) else str(field).encode("utf-8")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)


def _require_directory(path, *, expected_uid, expected_gid, mode=None):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise WorkerRuntimeError("Worker runtime directory is unavailable") from error
    if (
        target.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (mode is not None and stat.S_IMODE(metadata.st_mode) != mode)
    ):
        raise WorkerRuntimeError("Worker runtime directory is unsafe")
    return metadata


def _require_regular_file(
    path,
    *,
    expected_uid,
    expected_gid,
    executable=None,
    maximum_bytes=None,
    exact_mode=None,
):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise WorkerRuntimeError("Worker runtime file is unavailable") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        target.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or mode & 0o022
        or (exact_mode is not None and mode != exact_mode)
        or (executable is True and not mode & stat.S_IXUSR)
        or (executable is False and mode & 0o111)
        or (maximum_bytes is not None and metadata.st_size > maximum_bytes)
    ):
        raise WorkerRuntimeError("Worker runtime file is unsafe")
    return metadata


def stable_file_sha256(
    path,
    *,
    expected_uid,
    expected_gid,
    maximum_bytes=None,
    expected_device=None,
    return_payload=False,
):
    target = pathlib.Path(path)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if not hasattr(os, "O_NOFOLLOW"):
        raise WorkerRuntimeError("Worker runtime no-follow boundary is unavailable")
    flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise WorkerRuntimeError("Worker runtime file could not be opened") from error
    digest = hashlib.sha256()
    payload_chunks = [] if return_payload else None
    try:
        initial = os.fstat(descriptor)
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_nlink != 1
            or initial.st_uid != expected_uid
            or initial.st_gid != expected_gid
            or stat.S_IMODE(initial.st_mode) & 0o022
            or (
                maximum_bytes is not None
                and initial.st_size > maximum_bytes
            )
            or (
                expected_device is not None
                and initial.st_dev != expected_device
            )
        ):
            raise WorkerRuntimeError("Worker runtime file is unsafe")
        remaining = maximum_bytes + 1 if maximum_bytes is not None else None
        while True:
            read_size = 1024 * 1024
            if remaining is not None:
                if remaining <= 0:
                    raise WorkerRuntimeError("Worker runtime file is too large")
                read_size = min(read_size, remaining)
            chunk = os.read(descriptor, read_size)
            if not chunk:
                break
            digest.update(chunk)
            if payload_chunks is not None:
                payload_chunks.append(chunk)
            if remaining is not None:
                remaining -= len(chunk)
        if _stable_identity(os.fstat(descriptor)) != _stable_identity(initial):
            raise WorkerRuntimeError("Worker runtime file changed while being read")
    finally:
        os.close(descriptor)
    result = (digest.hexdigest(), initial)
    if payload_chunks is not None:
        return (*result, b"".join(payload_chunks))
    return result


def validate_package_lock(path, *, expected_uid, expected_gid):
    lock_path = pathlib.Path(path)
    lock_hash, metadata, payload = stable_file_sha256(
        lock_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        maximum_bytes=MAX_PACKAGE_LOCK_BYTES,
        return_payload=True,
    )
    try:
        document = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WorkerRuntimeError("Worker package lock is invalid") from error
    if len(payload) != metadata.st_size:
        raise WorkerRuntimeError("Worker package lock changed while being parsed")
    packages = document.get("packages") if isinstance(document, dict) else None
    wrangler = packages.get("node_modules/wrangler") if isinstance(packages, dict) else None
    bin_entries = wrangler.get("bin") if isinstance(wrangler, dict) else None
    if (
        not isinstance(wrangler, dict)
        or wrangler.get("version") != WRANGLER_VERSION
        or not isinstance(wrangler.get("integrity"), str)
        or not wrangler["integrity"].startswith("sha512-")
        or not isinstance(bin_entries, dict)
        or bin_entries.get("wrangler") != "bin/wrangler.js"
    ):
        raise WorkerRuntimeError("Worker package lock does not pin the required Wrangler")
    return lock_hash


def remove_bin_links(node_modules):
    bin_path = pathlib.Path(node_modules) / ".bin"
    try:
        metadata = bin_path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise WorkerRuntimeError("Worker .bin directory is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode):
        bin_path.unlink()
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise WorkerRuntimeError("Worker .bin path is unsafe")
    directory_fd = None
    try:
        directory_fd = os.open(
            bin_path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        entries = list(os.scandir(bin_path))
        for entry in entries:
            entry_metadata = entry.stat(follow_symlinks=False)
            if not (
                stat.S_ISLNK(entry_metadata.st_mode)
                or stat.S_ISREG(entry_metadata.st_mode)
            ):
                raise WorkerRuntimeError("Worker .bin contains an unsafe entry")
            os.unlink(entry.name, dir_fd=directory_fd)
        bin_path.rmdir()
    except WorkerRuntimeError:
        raise
    except OSError as error:
        raise WorkerRuntimeError("Worker .bin directory could not be removed") from error
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def secure_runtime_permissions(node_modules, *, expected_uid, expected_gid):
    root = pathlib.Path(node_modules)
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = pathlib.Path(current)
        current_metadata = current_path.lstat()
        if stat.S_ISLNK(current_metadata.st_mode):
            raise WorkerRuntimeError("Worker runtime contains a symlink")
        os.chmod(current_path, stat.S_IMODE(current_metadata.st_mode) & ~0o022)
        for name in (*directories, *files):
            path = current_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise WorkerRuntimeError("Worker runtime contains a symlink")
            if not (
                stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISREG(metadata.st_mode)
            ):
                raise WorkerRuntimeError("Worker runtime contains a special file")
            if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
                raise WorkerRuntimeError("Worker runtime ownership is unsafe")
            os.chmod(path, stat.S_IMODE(metadata.st_mode) & ~0o022)


def runtime_tree_sha256(node_modules, *, expected_uid, expected_gid):
    root = pathlib.Path(node_modules)
    root_metadata = _require_directory(
        root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    root_device = root_metadata.st_dev
    digest = hashlib.sha256()
    entry_count = 0
    stack = [(pathlib.Path("."), root)]
    while stack:
        relative, directory = stack.pop()
        initial = directory.lstat()
        if (
            not stat.S_ISDIR(initial.st_mode)
            or stat.S_ISLNK(initial.st_mode)
            or initial.st_dev != root_device
            or initial.st_uid != expected_uid
            or initial.st_gid != expected_gid
            or stat.S_IMODE(initial.st_mode) & 0o022
        ):
            raise WorkerRuntimeError("Worker runtime directory entry is unsafe")
        _hash_record(
            digest,
            b"directory",
            relative.as_posix(),
            f"{stat.S_IMODE(initial.st_mode):04o}",
        )
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise WorkerRuntimeError("Worker runtime tree could not be inspected") from error
        child_directories = []
        for entry in entries:
            entry_count += 1
            if entry_count > MAX_RUNTIME_FILES:
                raise WorkerRuntimeError("Worker runtime tree contains too many entries")
            child_relative = relative / entry.name
            child_path = directory / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise WorkerRuntimeError("Worker runtime contains a symlink")
            if (
                metadata.st_dev != root_device
                or metadata.st_uid != expected_uid
                or metadata.st_gid != expected_gid
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise WorkerRuntimeError("Worker runtime entry is unsafe")
            if stat.S_ISDIR(metadata.st_mode):
                child_directories.append((child_relative, child_path))
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise WorkerRuntimeError(
                    "Worker runtime files must be single-link regular files"
                )
            content_hash, stable_metadata = stable_file_sha256(
                child_path,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                expected_device=root_device,
            )
            _hash_record(
                digest,
                b"file",
                child_relative.as_posix(),
                f"{stat.S_IMODE(stable_metadata.st_mode):04o}",
                stable_metadata.st_size,
                content_hash,
            )
        if _stable_identity(directory.lstat()) != _stable_identity(initial):
            raise WorkerRuntimeError(
                "Worker runtime directory changed while being inspected"
            )
        stack.extend(reversed(child_directories))
    return digest.hexdigest()


def minimal_environment():
    return {
        "PATH": SAFE_PATH,
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "NPM_CONFIG_USERCONFIG": "/dev/null",
        "NPM_CONFIG_GLOBALCONFIG": "/dev/null",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
    }


def current_git_head(repo_dir, *, runner=subprocess.run):
    try:
        result = runner(
            [
                GIT_BINARY,
                "-C",
                pathlib.Path(repo_dir),
                "rev-parse",
                "--verify",
                "HEAD^{commit}",
            ],
            env=minimal_environment(),
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WorkerRuntimeError("Worker release Git identity is unavailable") from error
    head = result.stdout.strip()
    if not GIT_HEAD_RE.fullmatch(head):
        raise WorkerRuntimeError("Worker release Git identity is invalid")
    return head


def current_node_version(*, runner=subprocess.run):
    try:
        result = runner(
            [NODE_BINARY, "--version"],
            env=minimal_environment(),
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WorkerRuntimeError("fixed Node.js runtime is unavailable") from error
    version = result.stdout.strip()
    matched = NODE_VERSION_RE.fullmatch(version)
    if matched is None or int(matched.group(1)) < 22:
        raise WorkerRuntimeError("Node.js 22 or newer is required")
    return version


def validate_state(document):
    if not isinstance(document, dict) or set(document) != {
        "version",
        "git_head",
        "package_lock_sha256",
        "node_modules_sha256",
        "node_version",
        "wrangler_entry",
        "wrangler_version",
    }:
        raise WorkerRuntimeError("Worker runtime attestation is invalid")
    if (
        document["version"] != STATE_VERSION
        or not isinstance(document["git_head"], str)
        or not GIT_HEAD_RE.fullmatch(document["git_head"])
        or not isinstance(document["package_lock_sha256"], str)
        or not SHA256_RE.fullmatch(document["package_lock_sha256"])
        or not isinstance(document["node_modules_sha256"], str)
        or not SHA256_RE.fullmatch(document["node_modules_sha256"])
        or not isinstance(document["node_version"], str)
        or NODE_VERSION_RE.fullmatch(document["node_version"]) is None
        or document["wrangler_entry"] != WRANGLER_ENTRY_WITHIN_WORKER.as_posix()
        or document["wrangler_version"] != WRANGLER_VERSION
    ):
        raise WorkerRuntimeError("Worker runtime attestation is invalid")
    return document


def open_state_directory(path, *, expected_uid, expected_gid, create=False):
    state_directory = pathlib.Path(path)
    if create:
        try:
            state_directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as error:
            raise WorkerRuntimeError(
                "Worker runtime state directory could not be created"
            ) from error
    _require_directory(
        state_directory,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        mode=0o700,
    )
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if not hasattr(os, "O_NOFOLLOW"):
        raise WorkerRuntimeError("Worker runtime no-follow boundary is unavailable")
    try:
        return os.open(state_directory, flags | os.O_NOFOLLOW)
    except OSError as error:
        raise WorkerRuntimeError(
            "Worker runtime state directory could not be opened"
        ) from error


@contextlib.contextmanager
def runtime_lock(
    state_directory,
    *,
    expected_uid,
    expected_gid,
    exclusive,
    create=False,
):
    directory_fd = open_state_directory(
        state_directory,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        create=create,
    )
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    if create:
        flags |= os.O_CREAT
    try:
        try:
            descriptor = os.open(
                LOCK_PATH.name,
                flags,
                0o600,
                dir_fd=directory_fd,
            )
        except OSError as error:
            raise WorkerRuntimeError("Worker runtime operation lock is unavailable") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != expected_uid
                or metadata.st_gid != expected_gid
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise WorkerRuntimeError("Worker runtime operation lock is unsafe")
            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            try:
                fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise WorkerRuntimeError(
                    "another Worker runtime operation is in progress"
                ) from error
            yield
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)


def write_state(path, document, *, expected_uid, expected_gid):
    state_path = pathlib.Path(path)
    validated = validate_state(document)
    payload = (
        json.dumps(validated, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    if len(payload) > MAX_STATE_BYTES:
        raise WorkerRuntimeError("Worker runtime attestation is too large")
    directory_fd = open_state_directory(
        state_path.parent,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    temporary = f".{state_path.name}.{os.getpid()}.{os.urandom(8).hex()}"
    descriptor = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short Worker runtime state write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary,
            state_path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except OSError as error:
        raise WorkerRuntimeError(
            "Worker runtime attestation could not be written"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=directory_fd)
        os.close(directory_fd)


def read_state(path, *, expected_uid, expected_gid):
    state_path = pathlib.Path(path)
    _require_regular_file(
        state_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        executable=False,
        maximum_bytes=MAX_STATE_BYTES,
        exact_mode=0o600,
    )
    try:
        payload = state_path.read_bytes()
        document = json.loads(payload.decode("ascii", "strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WorkerRuntimeError("Worker runtime attestation is invalid") from error
    if len(payload) > MAX_STATE_BYTES:
        raise WorkerRuntimeError("Worker runtime attestation is too large")
    return validate_state(document)


def build_attestation(
    repo_dir,
    *,
    expected_uid,
    expected_gid,
    git_head,
    node_version,
):
    repo = pathlib.Path(repo_dir)
    worker = repo / WORKER_RELATIVE_PATH
    lock_hash = validate_package_lock(
        repo / PACKAGE_LOCK_RELATIVE_PATH,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    entry = worker / WRANGLER_ENTRY_WITHIN_WORKER
    _require_regular_file(
        entry,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    return validate_state(
        {
            "version": STATE_VERSION,
            "git_head": git_head,
            "package_lock_sha256": lock_hash,
            "node_modules_sha256": runtime_tree_sha256(
                repo / NODE_MODULES_RELATIVE_PATH,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            ),
            "node_version": node_version,
            "wrangler_entry": WRANGLER_ENTRY_WITHIN_WORKER.as_posix(),
            "wrangler_version": WRANGLER_VERSION,
        }
    )


def verify_attestation(
    repo_dir,
    state_path,
    *,
    expected_uid,
    expected_gid,
    git_head,
    node_version,
):
    state = read_state(
        state_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    expected = build_attestation(
        repo_dir,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        git_head=git_head,
        node_version=node_version,
    )
    if state != expected:
        raise WorkerRuntimeError(
            "Worker runtime attestation does not match the release"
        )
    return state


def require_production_context():
    repo = pathlib.Path(__file__).resolve().parents[1]
    source = repo / SOURCE_RELATIVE_PATH
    if os.geteuid() != 0 or repo != TRUSTED_RELEASE_ROOT:
        raise WorkerRuntimeError(
            "Worker runtime operations require root from the trusted production release"
        )
    for directory in (
        pathlib.Path("/"),
        TRUSTED_RELEASE_ROOT.parent,
        TRUSTED_RELEASE_ROOT,
        TRUSTED_RELEASE_ROOT / "deploy",
        TRUSTED_RELEASE_ROOT / WORKER_RELATIVE_PATH,
    ):
        _require_directory(directory, expected_uid=0, expected_gid=0)
    _require_regular_file(
        source,
        expected_uid=0,
        expected_gid=0,
        executable=False,
    )
    return repo


def run_release_guard(repo_dir):
    try:
        subprocess.run(
            [repo_dir / RELEASE_GUARD_RELATIVE_PATH, "check"],
            cwd=repo_dir,
            env=minimal_environment(),
            stdin=subprocess.DEVNULL,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WorkerRuntimeError("Worker release guard failed") from error


def prepare_runtime(repo_dir):
    repo = pathlib.Path(repo_dir)
    worker = repo / WORKER_RELATIVE_PATH
    run_release_guard(repo)
    environment = minimal_environment()
    environment["NPM_CONFIG_CACHE"] = str(STATE_DIRECTORY / "npm-cache")
    try:
        subprocess.run(
            [
                NPM_BINARY,
                "--prefix",
                worker,
                "ci",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
            cwd=worker,
            env=environment,
            stdin=subprocess.DEVNULL,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise WorkerRuntimeError("locked Worker dependency installation failed") from error
    node_modules = repo / NODE_MODULES_RELATIVE_PATH
    remove_bin_links(node_modules)
    secure_runtime_permissions(node_modules, expected_uid=0, expected_gid=0)
    run_release_guard(repo)
    state = build_attestation(
        repo,
        expected_uid=0,
        expected_gid=0,
        git_head=current_git_head(repo),
        node_version=current_node_version(),
    )
    write_state(STATE_PATH, state, expected_uid=0, expected_gid=0)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments not in (["prepare"], ["verify"]):
        raise WorkerRuntimeError(
            "usage: worker-runtime-attestation.py prepare|verify"
        )
    repo = require_production_context()
    mode = arguments[0]
    with runtime_lock(
        STATE_DIRECTORY,
        expected_uid=0,
        expected_gid=0,
        exclusive=mode == "prepare",
        create=mode == "prepare",
    ):
        if mode == "prepare":
            prepare_runtime(repo)
            print("Worker runtime prepared and attested")
        else:
            run_release_guard(repo)
            state = read_state(
                STATE_PATH,
                expected_uid=0,
                expected_gid=0,
            )
            verify_attestation(
                repo,
                STATE_PATH,
                expected_uid=0,
                expected_gid=0,
                git_head=current_git_head(repo),
                node_version=state["node_version"],
            )
            if current_node_version() != state["node_version"]:
                raise WorkerRuntimeError(
                    "fixed Node.js runtime changed after attestation"
                )
            print("Worker runtime attestation verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except WorkerRuntimeError as error:
        raise SystemExit(str(error)) from None
