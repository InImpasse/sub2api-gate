#!/usr/bin/python3 -I
import base64
import getpass
import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys


WRANGLER_VERSION = "4.112.0"
MAX_SECRET_LIST_BYTES = 64 * 1024
TRUSTED_FILESYSTEM_ROOT = pathlib.Path("/")
TRUSTED_RELEASE_ROOT = pathlib.Path("/opt/sub2api-gate-release")
TRUSTED_RELEASE_PARENT = TRUSTED_RELEASE_ROOT.parent
SECRET_INITIALIZER_SOURCE_RELATIVE_PATH = pathlib.Path(
    "deploy/generate-worker-secrets.py"
)
RELEASE_GUARD_RELATIVE_PATH = pathlib.Path("deploy/require-clean-worktree.sh")
RUNTIME_ATTESTOR_RELATIVE_PATH = pathlib.Path(
    "deploy/worker-runtime-attestation.py"
)
TRUSTED_RELEASE_DIRECTORIES = (
    pathlib.Path("deploy"),
    pathlib.Path("worker-allow-ip"),
)
PRIVATE_WRANGLER_CONFIG_RELATIVE_PATH = pathlib.Path(
    "worker-allow-ip/wrangler.private.jsonc"
)
SAFE_WRANGLER_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
NODE_BINARY = pathlib.Path("/usr/bin/node")
PYTHON_BINARY = pathlib.Path("/usr/bin/python3")
WRANGLER_ENTRY_RELATIVE_PATH = pathlib.Path(
    "worker-allow-ip/node_modules/wrangler/bin/wrangler.js"
)

MANAGED_SECRET_NAMES = (
    "ADMIN_PASSWORD_PBKDF2",
    "CREDENTIAL_ENCRYPTION_KEY",
    "INVITE_ACCESS_HMAC_KEY",
)
HMAC_STATE_RELATIVE_PATH = pathlib.Path(
    ".local/worker-secret-state/invite-access-hmac-migration.key"
)
HMAC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{64}$")


class SecretInitializationError(RuntimeError):
    pass


def base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _validate_state_parent(parent, expected_uid, *, create=False):
    parent = pathlib.Path(parent)
    if create:
        try:
            parent.mkdir(mode=0o700, parents=True)
        except FileExistsError:
            pass
    try:
        metadata = parent.lstat()
    except OSError as error:
        raise SecretInitializationError("private HMAC state directory is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or parent.resolve(strict=True) != parent.absolute()
    ):
        raise SecretInitializationError(
            "private HMAC state directory must be owned by the operator with mode 0700"
        )
    return parent


def _open_hmac_state(state_path, expected_uid, *, missing_ok=False, writable=False):
    state_path = pathlib.Path(state_path)
    _validate_state_parent(state_path.parent, expected_uid)
    flags = (os.O_RDWR if writable else os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(state_path, flags)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise SecretInitializationError("private HMAC migration state is missing") from None
    except OSError as error:
        raise SecretInitializationError("private HMAC migration state is unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 65
        ):
            raise SecretInitializationError(
                "private HMAC migration state must be a single-link operator-owned 0600 file"
            )
        raw = os.read(descriptor, 66)
        after = os.fstat(descriptor)
        if (
            len(raw) != 65
            or not raw.endswith(b"\n")
            or (metadata.st_dev, metadata.st_ino, metadata.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
        ):
            raise SecretInitializationError("private HMAC migration state is invalid")
        try:
            value = raw[:-1].decode("ascii")
        except UnicodeDecodeError as error:
            raise SecretInitializationError("private HMAC migration state is invalid") from error
        if not HMAC_KEY_PATTERN.fullmatch(value):
            raise SecretInitializationError("private HMAC migration state is invalid")
        return descriptor, metadata, value
    except Exception:
        os.close(descriptor)
        raise


def read_hmac_state(state_path, expected_uid, *, missing_ok=False):
    opened = _open_hmac_state(state_path, expected_uid, missing_ok=missing_ok)
    if opened is None:
        return None
    descriptor, _, value = opened
    os.close(descriptor)
    return value


def _fsync_directory(parent):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_temporary_secret(path):
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        size = os.fstat(descriptor).st_size
        if size:
            cleared = 0
            zeros = b"\0" * size
            while cleared < size:
                cleared += os.write(descriptor, zeros[cleared:])
            os.fsync(descriptor)
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            pathlib.Path(path).unlink()
        except FileNotFoundError:
            pass


def create_or_read_hmac_state(state_path, expected_uid, generated_value):
    if not HMAC_KEY_PATTERN.fullmatch(generated_value):
        raise SecretInitializationError("generated HMAC migration state is invalid")
    state_path = pathlib.Path(state_path)
    parent = _validate_state_parent(state_path.parent, expected_uid, create=True)
    existing = read_hmac_state(state_path, expected_uid, missing_ok=True)
    if existing is not None:
        return existing

    temporary = parent / f".{state_path.name}.tmp-{secrets.token_hex(16)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        payload = (generated_value + "\n").encode("ascii")
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    try:
        try:
            os.link(temporary, state_path, follow_symlinks=False)
        except FileExistsError:
            _remove_temporary_secret(temporary)
            return read_hmac_state(state_path, expected_uid)
        temporary.unlink()
        _fsync_directory(parent)
        return read_hmac_state(state_path, expected_uid)
    except Exception:
        if temporary.exists():
            _remove_temporary_secret(temporary)
        raise


def destroy_hmac_state(state_path, expected_uid):
    state_path = pathlib.Path(state_path)
    opened = _open_hmac_state(state_path, expected_uid, writable=True)
    descriptor, metadata, _ = opened
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        cleared = 0
        zeros = b"\0" * metadata.st_size
        while cleared < metadata.st_size:
            cleared += os.write(descriptor, zeros[cleared:])
        os.fsync(descriptor)
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        current = state_path.lstat()
        if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise SecretInitializationError("private HMAC migration state changed during deletion")
        state_path.unlink()
        _fsync_directory(state_path.parent)
    finally:
        os.close(descriptor)


def require_ignored_state_path(repo_dir, state_path, runner=subprocess.run, child_env=None):
    repo_dir = pathlib.Path(repo_dir).resolve()
    state_path = pathlib.Path(state_path).resolve(strict=False)
    try:
        relative = state_path.relative_to(repo_dir)
    except ValueError as error:
        raise SecretInitializationError("private HMAC state path must stay inside the repository") from error
    options = {
        "capture_output": True,
        "text": True,
        "check": False,
    }
    if child_env is not None:
        options["env"] = child_env
    result = runner(
        ["/usr/bin/git", "-C", repo_dir, "check-ignore", "--quiet", "--", relative],
        **options,
    )
    if result.returncode != 0:
        raise SecretInitializationError("private HMAC state path is not ignored by Git")


def build_wrangler_environment(_source=None):
    """Return the complete, minimal environment for root-owned Wrangler calls."""
    return {
        "PATH": SAFE_WRANGLER_PATH,
        "HOME": "/root",
        "WRANGLER_SEND_METRICS": "false",
        "CLOUDFLARE_INCLUDE_PROCESS_ENV": "false",
        "CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV": "false",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }


def _require_trusted_release_path(
    path,
    *,
    expects_directory,
    expects_executable=False,
    expects_single_link=False,
    expected_uid=0,
    expected_gid=0,
):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise SecretInitializationError("trusted Worker release path is unavailable") from error
    if (
        not target.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or (expects_directory and not stat.S_ISDIR(metadata.st_mode))
        or (not expects_directory and not stat.S_ISREG(metadata.st_mode))
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (expects_single_link and metadata.st_nlink != 1)
        or (expects_executable and not metadata.st_mode & stat.S_IXUSR)
    ):
        raise SecretInitializationError("trusted Worker release path is unsafe")


def _require_trusted_private_wrangler_config(path, *, expected_uid=0, expected_gid=0):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise SecretInitializationError("trusted private Wrangler config is unavailable") from error
    if (
        not target.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise SecretInitializationError(
            "trusted private Wrangler config must be a root-owned single-link mode-0600 regular file"
        )


def require_trusted_release_tree(
    repo_dir,
    wrangler_config,
    *,
    source_path=None,
    release_guard=None,
    trusted_root=None,
    expected_uid=0,
    expected_gid=0,
):
    repo_dir = pathlib.Path(repo_dir)
    trusted_root = pathlib.Path(
        TRUSTED_RELEASE_ROOT if trusted_root is None else trusted_root
    )
    if not trusted_root.is_absolute() or repo_dir != trusted_root:
        raise SecretInitializationError(
            "Worker Secret initialization requires the trusted production release tree"
        )
    source_path = (
        pathlib.Path(__file__).absolute()
        if source_path is None
        else pathlib.Path(source_path)
    )
    expected_source = trusted_root / SECRET_INITIALIZER_SOURCE_RELATIVE_PATH
    expected_guard = trusted_root / RELEASE_GUARD_RELATIVE_PATH
    expected_attestor = trusted_root / RUNTIME_ATTESTOR_RELATIVE_PATH
    expected_config = trusted_root / PRIVATE_WRANGLER_CONFIG_RELATIVE_PATH
    if source_path != expected_source or pathlib.Path(release_guard or expected_guard) != expected_guard:
        raise SecretInitializationError(
            "Worker Secret initialization requires the trusted production release tree"
        )
    if pathlib.Path(wrangler_config) != expected_config:
        raise SecretInitializationError(
            "Worker Secret initialization does not accept a Wrangler config override"
        )
    for path, expects_directory, expects_executable, expects_single_link in (
        (TRUSTED_FILESYSTEM_ROOT, True, False, False),
        (trusted_root.parent, True, False, False),
        (trusted_root, True, False, False),
        *((trusted_root / value, True, False, False) for value in TRUSTED_RELEASE_DIRECTORIES),
        (expected_source, False, False, True),
        (expected_guard, False, True, True),
        (expected_attestor, False, False, True),
    ):
        _require_trusted_release_path(
            path,
            expects_directory=expects_directory,
            expects_executable=expects_executable,
            expects_single_link=expects_single_link,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    _require_trusted_private_wrangler_config(
        expected_config,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )


def require_production_apply_context(
    repo_dir, wrangler_config, *, release_guard=None, streams=None
):
    if os.geteuid() != 0 or repo_dir != TRUSTED_RELEASE_ROOT:
        raise SecretInitializationError(
            "Worker Secret initialization requires root from the trusted production release tree"
        )
    if streams is None:
        streams = (sys.stdin, sys.stdout, sys.stderr)
    try:
        private_tty = all(stream.isatty() for stream in streams)
    except (AttributeError, OSError, ValueError):
        private_tty = False
    if not private_tty:
        raise SecretInitializationError(
            "Worker Secret initialization requires a private interactive TTY"
        )
    if "SUB2API_WRANGLER_CONFIG" in os.environ:
        raise SecretInitializationError(
            "Worker Secret initialization does not accept a Wrangler config override"
        )
    require_trusted_release_tree(
        repo_dir,
        wrangler_config,
        release_guard=release_guard,
    )


def load_managed_secret_names(manifest_path):
    try:
        manifest = json.loads(pathlib.Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SecretInitializationError("required Worker Secret manifest is invalid") from error
    required = manifest.get("required") if isinstance(manifest, dict) else None
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != 1
        or not isinstance(required, list)
        or any(not isinstance(name, str) for name in required)
        or any(name not in required for name in MANAGED_SECRET_NAMES)
    ):
        raise SecretInitializationError(
            "required Worker Secret manifest does not declare every managed secret"
        )
    return MANAGED_SECRET_NAMES


def parse_secret_names(raw):
    if len(raw.encode("utf-8")) > MAX_SECRET_LIST_BYTES:
        raise SecretInitializationError("remote Worker Secret name list is too large")
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as error:
        raise SecretInitializationError("remote Worker Secret name list is invalid") from error
    if not isinstance(entries, list):
        raise SecretInitializationError("remote Worker Secret name list is invalid")
    names = set()
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("name"), str)
            or not entry["name"]
        ):
            raise SecretInitializationError("remote Worker Secret name list is invalid")
        names.add(entry["name"])
    return names


def read_remote_secret_names(runner, wrangler, wrangler_config, child_env):
    result = runner(
        [NODE_BINARY, wrangler, "secret", "list", "--format", "json", "--config", wrangler_config],
        cwd=wrangler.parents[3],
        env=child_env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SecretInitializationError("Wrangler could not list remote Worker Secret names")
    return parse_secret_names(result.stdout)


def generate_missing_values(missing, password_reader=getpass.getpass, hmac_key=None):
    generated = {}
    if "ADMIN_PASSWORD_PBKDF2" in missing:
        password = password_reader("Admin password: ")
        confirmation = password_reader("Confirm admin password: ")
        if password != confirmation:
            raise SecretInitializationError("passwords do not match")
        if len(password) < 16:
            raise SecretInitializationError("admin password must be at least 16 characters")
        iterations = 310_000
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        generated["ADMIN_PASSWORD_PBKDF2"] = (
            "pbkdf2_sha256"
            + "$" + str(iterations)
            + "$" + base64url(salt)
            + "$" + base64url(digest)
        )
        del password, confirmation, digest
    if "CREDENTIAL_ENCRYPTION_KEY" in missing:
        generated["CREDENTIAL_ENCRYPTION_KEY"] = base64url(secrets.token_bytes(32))
    if "INVITE_ACCESS_HMAC_KEY" in missing:
        if not hmac_key or not HMAC_KEY_PATTERN.fullmatch(hmac_key):
            raise SecretInitializationError("private HMAC migration state was not prepared")
        generated["INVITE_ACCESS_HMAC_KEY"] = hmac_key
    return generated


def initialize_missing_secrets(
    *,
    runner,
    wrangler,
    wrangler_config,
    manifest_path,
    release_guard,
    child_env,
    hmac_state_path,
    expected_uid,
    password_reader=getpass.getpass,
):
    managed = load_managed_secret_names(manifest_path)
    runner(
        [release_guard, "check"],
        cwd=release_guard.parent.parent,
        env=child_env,
        check=True,
    )

    before = read_remote_secret_names(runner, wrangler, wrangler_config, child_env)
    missing = tuple(name for name in managed if name not in before)
    if not missing:
        return ()

    non_hmac_missing = tuple(
        name for name in missing if name != "INVITE_ACCESS_HMAC_KEY"
    )
    generated = generate_missing_values(
        non_hmac_missing,
        password_reader=password_reader,
    )
    if "INVITE_ACCESS_HMAC_KEY" in missing:
        generated["INVITE_ACCESS_HMAC_KEY"] = create_or_read_hmac_state(
            hmac_state_path,
            expected_uid,
            secrets.token_urlsafe(48),
        )

    # Password entry can take time. Recheck immediately before the bulk write so
    # a secret initialized by another operator is never intentionally replaced.
    current = read_remote_secret_names(runner, wrangler, wrangler_config, child_env)
    still_missing = tuple(name for name in missing if name not in current)
    if "INVITE_ACCESS_HMAC_KEY" in missing and "INVITE_ACCESS_HMAC_KEY" not in still_missing:
        generated.clear()
        destroy_hmac_state(hmac_state_path, expected_uid)
        raise SecretInitializationError(
            "remote HMAC Secret appeared concurrently; controlled rotation is required"
        )
    payload = {name: generated[name] for name in still_missing}
    generated.clear()
    if not payload:
        return ()

    serialized = json.dumps(payload, separators=(",", ":"))
    result = runner(
        [NODE_BINARY, wrangler, "secret", "bulk", "--config", wrangler_config],
        cwd=wrangler.parents[3],
        env=child_env,
        input=serialized,
        capture_output=True,
        text=True,
        check=False,
    )
    payload.clear()
    del serialized
    if result.returncode != 0:
        raise SecretInitializationError(
            "Wrangler bulk secret initialization failed; no secret value was logged"
        )

    after = read_remote_secret_names(runner, wrangler, wrangler_config, child_env)
    if any(name not in after for name in still_missing):
        raise SecretInitializationError(
            "remote Worker Secret name verification failed after bulk initialization"
        )
    return still_missing


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    mode = argv[0] if argv else "check"
    if mode not in {"check", "--apply"} or len(argv) > 1:
        raise SecretInitializationError(
            "usage: generate-worker-secrets.py [check|--apply]"
        )
    if mode != "--apply":
        print("check only; no remote secret list was read and no secret was generated")
        print(
            "rerun with --apply in a private terminal to initialize only missing managed Worker Secrets"
        )
        return 0
    repo_dir = pathlib.Path(__file__).absolute().parents[1]
    worker_dir = repo_dir / "worker-allow-ip"
    wrangler = repo_dir / WRANGLER_ENTRY_RELATIVE_PATH
    wrangler_config = repo_dir / PRIVATE_WRANGLER_CONFIG_RELATIVE_PATH
    manifest_path = worker_dir / "required-secrets.json"
    release_guard = repo_dir / RELEASE_GUARD_RELATIVE_PATH
    runtime_attestor = repo_dir / RUNTIME_ATTESTOR_RELATIVE_PATH
    hmac_state_path = repo_dir / HMAC_STATE_RELATIVE_PATH
    require_production_apply_context(
        repo_dir,
        wrangler_config,
        release_guard=release_guard,
    )
    child_env = build_wrangler_environment()
    subprocess.run(
        [release_guard, "check"],
        cwd=repo_dir,
        env=child_env,
        check=True,
    )
    subprocess.run(
        [PYTHON_BINARY, "-I", runtime_attestor, "verify"],
        cwd=repo_dir,
        env=child_env,
        check=True,
    )
    if not wrangler.is_file() or wrangler.is_symlink():
        raise SecretInitializationError("attested Wrangler entry is missing")
    version = subprocess.run(
        [NODE_BINARY, wrangler, "--version"],
        cwd=worker_dir,
        env=child_env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if version != WRANGLER_VERSION:
        raise SecretInitializationError(f"locked Wrangler {WRANGLER_VERSION} is required")
    require_ignored_state_path(repo_dir, hmac_state_path, child_env=child_env)

    initialized = initialize_missing_secrets(
        runner=subprocess.run,
        wrangler=wrangler,
        wrangler_config=wrangler_config,
        manifest_path=manifest_path,
        release_guard=release_guard,
        child_env=child_env,
        hmac_state_path=hmac_state_path,
        expected_uid=os.geteuid(),
    )
    if initialized:
        print(
            f"initialized and name-verified {len(initialized)} missing managed Worker Secret(s)"
        )
    else:
        print("managed Worker Secrets already exist; no password was read and no value was changed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SecretInitializationError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
