#!/usr/bin/env python3
import hashlib
import os
import pathlib
import secrets
import stat
import subprocess
import sys


REPO_DIR = pathlib.Path(__file__).resolve().parent.parent
DEPLOY_DIR = REPO_DIR / "deploy"
if str(DEPLOY_DIR) not in sys.path:
    sys.path.insert(0, str(DEPLOY_DIR))

from private_env import PrivateEnvironmentError, read_private_environment


EXPECTED_DATA_ROOT = pathlib.Path("/mnt/data/sub2api-gate")
ACL_OWNER_UID = 999
ACL_OWNER_GID = 1000
ACL_MODE = 0o400
APPLICATION_ACL_FILENAME = "users.acl"
NONCE_ACL_FILENAME = "nonce-users.acl"

# Audited against Sub2API v0.1.176, source revision
# e803e3851c0a7e222cfadeafad7b8636ab959d11. Request-derived routing hashes and
# wait counters are allowed only because the application Redis is tmpfs-backed
# with RDB/AOF disabled. Prompt payloads, moderation data, image jobs, and every
# unknown namespace remain omitted.
SUB2API_KEY_PATTERNS = (
    "apikey:*",
    "billing:*",
    "concurrency:*",
    "cyber_session_block:*",
    "dashboard:stats:v1",
    "error_passthrough_rules",
    "fingerprint:*",
    "internal500_count:account:*",
    "leader:lock:*",
    "masked_session:*",
    "notify_code_user_rate:*",
    "notify_verify:*",
    "oauth:*",
    "openai_403_count:account:*",
    "ops:*",
    "password_reset:*",
    "password_reset_sent:*",
    "proxy:latency:*",
    "rate_limit:*",
    "redeem:*",
    "refresh_token:*",
    "rpm:*",
    "sched:*",
    "session_limit:account:*",
    "sticky_session:*",
    "sub2api:dashboard:*",
    "temp_unsched:account:*",
    "timeout_count:account:*",
    "tls_fingerprint_profiles",
    "token_family:*",
    "totp:*",
    "umq:*",
    "update:latest",
    "user_refresh_tokens:*",
    "verify_code:*",
    "wait:account:*",
    "websearch:*",
    "window_cost:account:*",
)
SUB2API_CHANNEL_PATTERNS = (
    "auth:cache:invalidate",
    "error_passthrough_rules_updated",
    "sub2api:prompt_guard:config:invalidate",
    "subscription:cache:invalidate",
    "tls_fingerprint_profiles_updated",
)


def validate_password(value, label):
    if not isinstance(value, str) or len(value) < 24:
        raise ValueError(f"{label} must contain at least 24 characters")
    if len(value) > 4096 or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise ValueError(f"{label} must contain visible ASCII characters only")


def password_hash(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def render_application_acl(default_password):
    validate_password(default_password, "REDIS_PASSWORD")
    default_rules = [
        "user default reset on",
        "#" + password_hash(default_password),
        "resetkeys",
        *("~" + pattern for pattern in SUB2API_KEY_PATTERNS),
        "resetchannels",
        *("&" + pattern for pattern in SUB2API_CHANNEL_PATTERNS),
        "+@all",
        "-@admin",
        "-@dangerous",
    ]
    return " ".join(default_rules) + "\n"


def render_nonce_acl(sync_password):
    validate_password(sync_password, "SUB2API_SYNC_REDIS_PASSWORD")
    sync_rules = [
        "user sub2api_sync reset on",
        "#" + password_hash(sync_password),
        "resetkeys",
        "~sub2api-sync:nonce:*",
        "resetchannels",
        "-@all",
        "+ping",
        "+set",
        "+ttl",
        "+select",
    ]
    return "user default off\n" + " ".join(sync_rules) + "\n"


def render_migration_acl(migration_password):
    """Return an ACL used only by an offline, one-time nonce import target."""
    validate_password(migration_password, "SUB2API_TARGET_REDIS_PASSWORD")
    migration_rules = [
        "user sub2api_migration reset on",
        "#" + password_hash(migration_password),
        "resetkeys",
        "~sub2api-sync:nonce:*",
        "resetchannels",
        "-@all",
        "+ping",
        "+info",
        "+dbsize",
        "+config|get",
        "+restore",
        "+unlink",
        "+select",
    ]
    return "user default off\n" + " ".join(migration_rules) + "\n"


def validate_distinct_passwords(default_password, sync_password):
    validate_password(default_password, "REDIS_PASSWORD")
    validate_password(sync_password, "SUB2API_SYNC_REDIS_PASSWORD")
    if default_password == sync_password:
        raise ValueError("Redis application and sync credentials must be distinct")


def validate_redis_directory(path):
    try:
        file_stat = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("Redis data directory is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(file_stat.st_mode):
        raise RuntimeError("Redis data directory must be a regular directory")
    if resolved != EXPECTED_DATA_ROOT / "redis":
        raise RuntimeError("Redis data directory resolves outside SUB2API_DATA_ROOT")
    if (file_stat.st_uid, file_stat.st_gid) != (ACL_OWNER_UID, ACL_OWNER_GID):
        raise RuntimeError("Redis data directory must be owned by 999:1000")
    if stat.S_IMODE(file_stat.st_mode) != 0o700:
        raise RuntimeError("Redis data directory must use mode 0700")
    return resolved


def write_acl_atomic(directory, filename, content):
    if filename not in {APPLICATION_ACL_FILENAME, NONCE_ACL_FILENAME}:
        raise RuntimeError("Redis ACL filename is not approved")
    target = directory / filename
    try:
        target_stat = target.stat(follow_symlinks=False)
    except FileNotFoundError:
        target_stat = None
    except OSError as error:
        raise RuntimeError("existing Redis ACL could not be inspected") from error
    if target_stat is not None and (
        target.is_symlink() or not stat.S_ISREG(target_stat.st_mode)
    ):
        raise RuntimeError("existing Redis ACL must be a regular file")

    temporary = directory / (
        f".{filename}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        payload = content.encode("ascii")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fchown(descriptor, ACL_OWNER_UID, ACL_OWNER_GID)
        os.fchmod(descriptor, ACL_MODE)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, target)
        directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        raise RuntimeError("Redis ACL could not be written atomically") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

    result = target.stat(follow_symlinks=False)
    if (
        target.is_symlink()
        or not stat.S_ISREG(result.st_mode)
        or (result.st_uid, result.st_gid) != (ACL_OWNER_UID, ACL_OWNER_GID)
        or stat.S_IMODE(result.st_mode) != ACL_MODE
    ):
        raise RuntimeError("Redis ACL permissions are unsafe after write")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    mode = "check"
    env_file = REPO_DIR / ".env"
    while arguments:
        argument = arguments.pop(0)
        if argument in {"check", "--apply"}:
            mode = argument
        elif argument == "--env-file" and arguments:
            env_file = pathlib.Path(arguments.pop(0))
        else:
            raise SystemExit(
                "usage: configure-redis-acl.py [check|--apply] [--env-file PATH]"
            )

    # Exercise every policy renderer without accessing runtime values.
    validate_distinct_passwords("D" * 32, "S" * 32)
    render_application_acl("D" * 32)
    render_nonce_acl("S" * 32)
    render_migration_acl("M" * 32)
    if mode != "--apply":
        print("Redis ACL policy check passed; no secret was read and no file was written")
        return 0

    subprocess.run(
        [REPO_DIR / "deploy" / "require-clean-worktree.sh"],
        cwd=REPO_DIR,
        check=True,
    )
    if os.geteuid() != 0:
        raise RuntimeError("Redis ACL apply requires root")
    values = read_private_environment(env_file)
    if values.get("SUB2API_DATA_ROOT") != str(EXPECTED_DATA_ROOT):
        raise RuntimeError("SUB2API_DATA_ROOT must be exactly /mnt/data/sub2api-gate")
    default_password = values.get("REDIS_PASSWORD", "")
    sync_password = values.get("SUB2API_SYNC_REDIS_PASSWORD", "")
    validate_distinct_passwords(default_password, sync_password)
    application_content = render_application_acl(default_password)
    nonce_content = render_nonce_acl(sync_password)
    directory = validate_redis_directory(EXPECTED_DATA_ROOT / "redis")
    write_acl_atomic(directory, APPLICATION_ACL_FILENAME, application_content)
    write_acl_atomic(directory, NONCE_ACL_FILENAME, nonce_content)
    print(
        "separate application and nonce Redis ACLs installed with hashed "
        "credentials and private ownership"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        PrivateEnvironmentError,
        RuntimeError,
        ValueError,
        subprocess.CalledProcessError,
    ) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
