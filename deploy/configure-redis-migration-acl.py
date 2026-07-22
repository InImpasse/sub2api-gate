#!/usr/bin/env python3
import importlib.util
import os
import pathlib
import secrets
import stat
import subprocess
import sys


REPO_DIR = pathlib.Path(__file__).resolve().parent.parent
RUNTIME_DIR = pathlib.Path("/run/sub2api-gate")
TARGET = RUNTIME_DIR / "redis-migration.acl"


def load_acl_module():
    path = REPO_DIR / "deploy" / "configure-redis-acl.py"
    spec = importlib.util.spec_from_file_location("sub2api_redis_acl", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mount_type_for(path):
    resolved = path.resolve(strict=True)
    best = None
    with open("/proc/self/mountinfo", encoding="utf-8") as mountinfo:
        for line in mountinfo:
            left, separator, right = line.partition(" - ")
            if not separator:
                continue
            fields = left.split()
            filesystem = right.split()[0]
            if len(fields) < 5:
                continue
            mount = pathlib.Path(
                fields[4]
                .replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\012", "\n")
                .replace("\\134", "\\")
            )
            try:
                resolved.relative_to(mount)
            except ValueError:
                continue
            if best is None or len(mount.parts) > len(best[0].parts):
                best = (mount, filesystem)
    return best[1] if best else None


def require_runtime_directory():
    if mount_type_for(pathlib.Path("/run")) not in {"tmpfs", "ramfs"}:
        raise RuntimeError("/run must be memory-backed before creating a migration ACL")
    try:
        RUNTIME_DIR.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = RUNTIME_DIR.stat(follow_symlinks=False)
    if (
        RUNTIME_DIR.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or (info.st_uid, info.st_gid) != (0, 0)
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RuntimeError("migration runtime directory must be root-owned mode 0700")


def install(content):
    require_runtime_directory()
    temporary = RUNTIME_DIR / f".redis-migration.{os.getpid()}.{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, 0o400)
        payload = content.encode("ascii")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        # The parent stays root-only; only the non-root Redis process can read
        # the bind-mounted one-time ACL file.
        os.fchown(descriptor, 999, 1000)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, TARGET)
        directory = os.open(RUNTIME_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def remove():
    try:
        info = TARGET.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    if (
        TARGET.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or (info.st_uid, info.st_gid) != (999, 1000)
        or stat.S_IMODE(info.st_mode) != 0o400
    ):
        raise RuntimeError("migration ACL cleanup target is unsafe")
    TARGET.unlink()
    directory = os.open(RUNTIME_DIR, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    mode = arguments.pop(0) if arguments else "check"
    env_file = REPO_DIR / ".env"
    if arguments[:1] == ["--env-file"] and len(arguments) == 2:
        env_file = pathlib.Path(arguments[1])
        arguments = []
    if arguments or mode not in {"check", "--apply", "--remove"}:
        raise RuntimeError(
            "usage: configure-redis-migration-acl.py "
            "[check|--apply|--remove] [--env-file PATH]"
        )

    acl = load_acl_module()
    acl.render_migration_acl("M" * 32)
    if mode == "check":
        print("one-time Redis migration ACL check passed; no secret was read and no file was written")
        return 0
    if os.geteuid() != 0:
        raise RuntimeError("Redis migration ACL changes require root")
    if mode == "--remove":
        remove()
        print("one-time Redis migration ACL removed")
        return 0

    subprocess.run(
        [REPO_DIR / "deploy" / "require-clean-worktree.sh"],
        cwd=REPO_DIR,
        check=True,
    )
    values = acl.read_private_environment(env_file)
    password = values.get("SUB2API_TARGET_REDIS_PASSWORD", "")
    for runtime_name in ("REDIS_PASSWORD", "SUB2API_SYNC_REDIS_PASSWORD"):
        if password and password == values.get(runtime_name):
            raise RuntimeError("migration Redis credential must be one-time and distinct")
    install(acl.render_migration_acl(password))
    print("one-time Redis migration ACL installed in memory-backed /run")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
