#!/usr/bin/env python3
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


class PrivateEnvironmentError(ValueError):
    pass


def read_private_environment(path):
    path = pathlib.Path(path)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise PrivateEnvironmentError(
                "private environment file must be a regular non-symlink file"
            ) from error
        raise PrivateEnvironmentError(
            "private environment file is unavailable"
        ) from error
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise PrivateEnvironmentError(
                "private environment file must be a regular non-symlink file"
            )
        if stat.S_IMODE(file_stat.st_mode) != 0o600:
            raise PrivateEnvironmentError(
                "private environment file must use mode 0600"
            )
        if file_stat.st_size > MAX_FILE_BYTES:
            raise PrivateEnvironmentError("private environment file is too large")
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
        source = payload.decode("utf-8")
    except PrivateEnvironmentError:
        raise
    except (OSError, UnicodeError) as error:
        raise PrivateEnvironmentError(
            "private environment file could not be read"
        ) from error
    finally:
        os.close(descriptor)

    values = {}
    for raw_line in source.splitlines():
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


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--emit-nul", action="store_true")
    parser.add_argument("path", nargs="?")
    arguments = parser.parse_args(argv)
    if not arguments.emit_nul or not arguments.path:
        print("usage: private_env.py --emit-nul PATH", file=sys.stderr)
        return 2
    if sys.stdout.isatty():
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
