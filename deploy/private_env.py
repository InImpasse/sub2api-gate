#!/usr/bin/python3 -I
"""Strict parser for private Compose environment files.

The accepted format intentionally has no quoting, escaping, interpolation, or
inline-comment syntax. This keeps every caller and Docker Compose from
assigning different meanings to a credential.
"""

import argparse
import errno
import os
import pathlib
import re
import stat
import sys


MAX_FILE_BYTES = 128 * 1024
MAX_ENTRIES = 256
MAX_LINE_CHARACTERS = 8192
KEY_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*\Z")
FORBIDDEN_KEY_PREFIXES = ("COMPOSE_", "DOCKER_")
FORBIDDEN_VALUE_CHARACTERS = frozenset("'\"\\#$")
PRODUCTION_PRIVATE_ENV_PATH = pathlib.Path("/mnt/data/sub2api-gate/private/.env")


class PrivateEnvironmentError(ValueError):
    pass


def _decode_private_environment(payload):
    index = 0
    while index < len(payload):
        byte = payload[index]
        if byte == 0x0D:
            if index + 1 >= len(payload) or payload[index + 1] != 0x0A:
                raise PrivateEnvironmentError(
                    "private environment file contains an invalid line separator"
                )
            index += 2
            continue
        if byte == 0x0A or 0x20 <= byte <= 0x7E:
            index += 1
            continue
        raise PrivateEnvironmentError(
            "private environment file must use visible ASCII and canonical line endings"
        )
    return payload.replace(b"\r\n", b"\n").decode("ascii")


def _stable_file_identity(file_stat):
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_mode,
        file_stat.st_nlink,
        file_stat.st_uid,
        file_stat.st_gid,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def _expected_operator_identity():
    expected_uid = os.geteuid()
    expected_gid = 0 if expected_uid == 0 else os.getegid()
    return expected_uid, expected_gid


def _normalize_private_environment_path(path, *, root_operator):
    path = pathlib.Path(path)
    if not path.is_absolute():
        raise PrivateEnvironmentError(
            "private environment file path must be absolute"
        )
    components = path.parts[1:]
    if not components or any(component in {"", ".", ".."} for component in components):
        raise PrivateEnvironmentError("private environment file path is invalid")
    if root_operator and path != PRODUCTION_PRIVATE_ENV_PATH:
        raise PrivateEnvironmentError(
            "root private environment must use the fixed root private environment path"
        )
    return path, components


def _validate_root_ancestor_directory(directory_stat):
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or directory_stat.st_uid != 0
        or directory_stat.st_gid != 0
        or stat.S_IMODE(directory_stat.st_mode) & 0o022
    ):
        raise PrivateEnvironmentError(
            "root private environment ancestor directory is unsafe"
        )


def _open_private_environment(path, expected_uid):
    path, components = _normalize_private_environment_path(
        path,
        root_operator=expected_uid == 0,
    )
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise PrivateEnvironmentError(
            "private environment file boundary is unavailable"
        )
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        directory_descriptor = os.open("/", directory_flags)
    except OSError as error:
        raise PrivateEnvironmentError(
            "private environment file is unavailable"
        ) from error
    try:
        for component in components[:-1]:
            if expected_uid == 0:
                _validate_root_ancestor_directory(os.fstat(directory_descriptor))
            try:
                next_descriptor = os.open(
                    component, directory_flags, dir_fd=directory_descriptor
                )
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise PrivateEnvironmentError(
                        "private environment file must be a regular non-symlink file"
                    ) from error
                raise PrivateEnvironmentError(
                    "private environment file is unavailable"
                ) from error
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        parent_stat = os.fstat(directory_descriptor)
        if expected_uid == 0:
            _validate_root_ancestor_directory(parent_stat)
        elif (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != expected_uid
            or stat.S_IMODE(parent_stat.st_mode) & 0o022
        ):
            raise PrivateEnvironmentError(
                "private environment parent directory is unsafe"
            )
        try:
            return os.open(
                components[-1], file_flags, dir_fd=directory_descriptor
            )
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise PrivateEnvironmentError(
                    "private environment file must be a regular non-symlink file"
                ) from error
            raise PrivateEnvironmentError(
                "private environment file is unavailable"
            ) from error
    finally:
        os.close(directory_descriptor)


def _identity_document(file_stat):
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


def _validate_private_environment_file(file_stat, *, expected_uid, expected_gid):
    if not stat.S_ISREG(file_stat.st_mode):
        raise PrivateEnvironmentError(
            "private environment file must be a regular non-symlink file"
        )
    if file_stat.st_nlink != 1:
        raise PrivateEnvironmentError(
            "private environment file must have a single filesystem link"
        )
    if (file_stat.st_uid, file_stat.st_gid) != (expected_uid, expected_gid):
        raise PrivateEnvironmentError(
            "private environment file must be owned by the expected operator"
        )
    if stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise PrivateEnvironmentError(
            "private environment file must use mode 0600"
        )
    if file_stat.st_size > MAX_FILE_BYTES:
        raise PrivateEnvironmentError("private environment file is too large")


def _read_private_environment_payload(path, *, expected_uid, expected_gid):
    descriptor = _open_private_environment(path, expected_uid)
    try:
        file_stat = os.fstat(descriptor)
        _validate_private_environment_file(
            file_stat,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        chunks = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_FILE_BYTES:
            raise PrivateEnvironmentError("private environment file is too large")
        final_stat = os.fstat(descriptor)
        if _stable_file_identity(final_stat) != _stable_file_identity(file_stat):
            raise PrivateEnvironmentError(
                "private environment file changed while being read"
            )
        return payload, _identity_document(final_stat)
    except PrivateEnvironmentError:
        raise
    except OSError as error:
        raise PrivateEnvironmentError(
            "private environment file could not be read"
        ) from error
    finally:
        os.close(descriptor)


def _parse_private_environment(payload):
    source = _decode_private_environment(payload)
    values = {}
    for raw_line in source.split("\n"):
        if len(raw_line) > MAX_LINE_CHARACTERS:
            raise PrivateEnvironmentError("private environment line is too long")
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        key, separator, value = raw_line.partition("=")
        if (
            not separator
            or not KEY_PATTERN.fullmatch(key)
            or key.startswith(FORBIDDEN_KEY_PREFIXES)
            or key in values
        ):
            raise PrivateEnvironmentError("private environment file is invalid")
        if any(
            ord(character) < 0x21
            or ord(character) > 0x7E
            or character in FORBIDDEN_VALUE_CHARACTERS
            for character in value
        ):
            raise PrivateEnvironmentError(
                "private environment values must use literal visible ASCII"
            )
        values[key] = value
        if len(values) > MAX_ENTRIES:
            raise PrivateEnvironmentError(
                "private environment file contains too many entries"
            )
    return values


def read_private_environment_with_identity(path):
    expected_uid, expected_gid = _expected_operator_identity()
    payload, identity = _read_private_environment_payload(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    return _parse_private_environment(payload), identity


def read_private_environment(path):
    values, _identity = read_private_environment_with_identity(path)
    return values


def private_environment_identity(path, *, expected_uid=None, expected_gid=None):
    operator_uid, operator_gid = _expected_operator_identity()
    if (
        (expected_uid is not None or expected_gid is not None)
        and (expected_uid, expected_gid) != (operator_uid, operator_gid)
    ):
        raise PrivateEnvironmentError(
            "private environment expected operator identity is invalid"
        )
    descriptor = _open_private_environment(path, operator_uid)
    try:
        file_stat = os.fstat(descriptor)
        _validate_private_environment_file(
            file_stat,
            expected_uid=operator_uid,
            expected_gid=operator_gid,
        )
        return _identity_document(file_stat)
    except PrivateEnvironmentError:
        raise
    except OSError as error:
        raise PrivateEnvironmentError(
            "private environment file could not be read"
        ) from error
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--emit-nul", action="store_true")
    parser.add_argument("path", nargs="?")
    arguments = parser.parse_args(argv)
    if not arguments.emit_nul or not arguments.path:
        print("usage: private_env.py --emit-nul PATH", file=sys.stderr)
        return 2
    try:
        output_stat = os.fstat(sys.stdout.fileno())
    except (AttributeError, OSError, ValueError):
        output_stat = None
    if output_stat is None or not stat.S_ISFIFO(output_stat.st_mode):
        print("private environment records require a protected pipe", file=sys.stderr)
        return 1
    try:
        values = read_private_environment(arguments.path)
    except PrivateEnvironmentError as error:
        print(str(error), file=sys.stderr)
        return 1
    output = sys.stdout.buffer
    for key, value in values.items():
        output.write(key.encode("ascii") + b"\0")
        output.write(value.encode("ascii") + b"\0")
    output.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
