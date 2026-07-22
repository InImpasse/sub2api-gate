#!/usr/bin/env python3
"""Test-only PostgreSQL client bridge used by the locked-stream PG18 gate."""

import os
import pathlib
import re
import sys


CONTAINER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def source_container(arguments):
    try:
        index = arguments.index("--source-postgres-container")
        container = arguments[index + 1]
        command_index = next(
            position
            for position, value in enumerate(arguments)
            if value in {"psql", "pg_dump"}
        )
    except (StopIteration, ValueError, IndexError):
        raise SystemExit(90)
    return container, arguments[command_index:]


def target_container(arguments):
    try:
        if arguments[0] != "--target-private-env-file":
            raise ValueError
        env_file = pathlib.Path(arguments[1])
        command = arguments[2:]
        line = env_file.read_text(encoding="ascii").strip()
        key, separator, container = line.partition("=")
    except (OSError, UnicodeError, ValueError, IndexError):
        raise SystemExit(91)
    if key != "TEST_TARGET_CONTAINER" or separator != "=" or not command:
        raise SystemExit(91)
    return container, command


def main():
    arguments = sys.argv[1:]
    if "--source-postgres-container" in arguments:
        container, command = source_container(arguments)
    else:
        container, command = target_container(arguments)
    if not CONTAINER_RE.fullmatch(container) or command[0] not in {"psql", "pg_dump"}:
        return 92
    docker_command = [
        "docker",
        "exec",
        "--interactive",
        "--user",
        "postgres",
    ]
    pgoptions = os.environ.get("SUB2API_PGOPTIONS", "")
    if pgoptions:
        docker_command.extend(("--env", f"PGOPTIONS={pgoptions}"))
    docker_command.extend(
        (
            container,
            *command,
            "--host=/var/run/postgresql",
            "--port=5432",
            "--username=postgres",
            "--dbname=postgres",
        )
    )
    os.execvp(docker_command[0], docker_command)


if __name__ == "__main__":
    raise SystemExit(main())
