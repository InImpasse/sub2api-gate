#!/usr/bin/env python3
"""Execute reviewed PostgreSQL clients against the exact legacy container."""

from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import urllib.parse
from typing import NamedTuple


REPO_DIR = pathlib.Path(__file__).resolve().parents[1]
PRIVATE_ENV_TOOL = REPO_DIR / "deploy" / "private_env.py"
PG_ENV_TOOL = REPO_DIR / "deploy" / "pg-env-exec.py"
DOCKER_SOCKET = pathlib.Path("/var/run/docker.sock")
CONTAINER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
PG_SYSTEM_ID_RE = re.compile(
    r"^Database system identifier:\s*([0-9]{10,24})\s*$", re.MULTILINE
)
DATABASE_IDENTITY_RE = re.compile(
    r"([0-9]{10,24})\|([0-9]{1,10})\|((?:[0-9a-f]{2}){1,63})\Z"
)
PG_SNAPSHOT_RE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9]+\Z")
PRIVATE_DOCKER_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
POSTGRES_ENV_TEMPLATE = (
    '{{range .Config.Env}}{{ $parts := split . "=" }}'
    '{{if or (eq (index $parts 0) "POSTGRES_USER") '
    '(eq (index $parts 0) "POSTGRES_DB")}}{{println .}}{{end}}{{end}}'
)
APP_DATABASE_ENV_TEMPLATE = (
    '{{range .Config.Env}}{{ $parts := split . "=" }}'
    '{{if or (eq (index $parts 0) "DATABASE_HOST") '
    '(or (eq (index $parts 0) "DATABASE_PORT") '
    '(eq (index $parts 0) "DATABASE_DBNAME"))}}{{println .}}{{end}}{{end}}'
)
NETWORK_INSPECT_TEMPLATE = (
    "{{.Id}}|{{.Name}}|{{.State.Running}}|{{json .NetworkSettings.Networks}}"
)
DATABASE_IDENTITY_SQL = (
    "SELECT system_identifier::text || '|' || d.oid::text || '|' || "
    "pg_catalog.encode(pg_catalog.convert_to(pg_catalog.current_database(), "
    "'UTF8'), 'hex') FROM pg_catalog.pg_control_system() "
    "CROSS JOIN pg_catalog.pg_database AS d "
    "WHERE d.datname = pg_catalog.current_database()"
)
IDENTITY_PGOPTIONS = (
    "-c default_transaction_read_only=on -c lock_timeout=1000 "
    "-c statement_timeout=5000 -c idle_in_transaction_session_timeout=5000"
)
MAX_METADATA_OUTPUT_BYTES = 64 * 1024
PSQL_FLAG_OPTIONS = frozenset(
    {"--no-align", "--no-psqlrc", "--quiet", "--tuples-only"}
)
PSQL_FIXED_VALUE_OPTIONS = {"-v": "ON_ERROR_STOP=1", "--set": "ON_ERROR_STOP=1"}
PG_DUMP_FLAG_OPTIONS = frozenset(
    {
        "--no-comments",
        "--no-large-objects",
        "--no-owner",
        "--no-privileges",
        "--no-publications",
        "--no-security-labels",
        "--no-subscriptions",
        "--no-tablespaces",
        "--schema-only",
        "--serializable-deferrable",
    }
)
PG_DUMP_FIXED_OPTIONS = frozenset({"--encoding=UTF8", "--format=plain"})


class SourcePostgresError(RuntimeError):
    pass


class RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "source PostgreSQL command validation failed\n")


class SourceUrl(NamedTuple):
    host: str
    port: int
    user: str
    database: str


class SourceBinding(NamedTuple):
    postgres_id: str
    user: str
    database: str
    system_identifier: str
    database_oid: str
    database_name_hex: str


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SourcePostgresError("source PostgreSQL helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_private_env_tool():
    return load_module(PRIVATE_ENV_TOOL, "source_postgres_private_env")


def load_pg_env_tool():
    return load_module(PG_ENV_TOOL, "source_postgres_target_env")


def docker_environment(environment=None):
    source = os.environ if environment is None else environment
    result = {
        name: source[name]
        for name in ("PATH", "LANG", "LC_ALL", "TZ")
        if source.get(name)
    }
    result.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    result["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    return result


def run_command(argv, *, timeout=10, environment=None):
    result = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=timeout,
        check=False,
        env=docker_environment(environment),
    )
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > MAX_METADATA_OUTPUT_BYTES:
        raise SourcePostgresError("source PostgreSQL metadata command failed")
    return result


def decoded_stdout(result):
    value = result.stdout
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise SourcePostgresError("source PostgreSQL metadata is invalid") from error
    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_METADATA_OUTPUT_BYTES:
        raise SourcePostgresError("source PostgreSQL metadata is invalid")
    return value.strip()


def parse_source_url(raw_url):
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except (TypeError, ValueError) as error:
        raise SourcePostgresError("source PostgreSQL URL is invalid") from error
    if (
        parsed.scheme not in {"postgres", "postgresql"}
        or parsed.fragment
        or not parsed.hostname
        or parsed.username is None
        or parsed.password is None
        or not parsed.path.startswith("/")
        or parsed.path.count("/") != 1
    ):
        raise SourcePostgresError("source PostgreSQL URL is invalid")
    try:
        port = parsed.port or 5432
        address = ipaddress.ip_address(parsed.hostname)
        user = urllib.parse.unquote(parsed.username, errors="strict")
        password = urllib.parse.unquote(parsed.password, errors="strict")
        database = urllib.parse.unquote(parsed.path[1:], errors="strict")
        query = urllib.parse.parse_qs(
            parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=1
        )
    except (UnicodeError, ValueError) as error:
        raise SourcePostgresError("source PostgreSQL URL is invalid") from error
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not any(address in network for network in PRIVATE_DOCKER_NETWORKS)
        or parsed.hostname != address.compressed
        or port != 5432
        or query != {"sslmode": ["disable"]}
    ):
        raise SourcePostgresError("source PostgreSQL URL is not a private container endpoint")
    for value in (user, password, database):
        if not value or "\x00" in value or any(ord(character) < 32 for character in value):
            raise SourcePostgresError("source PostgreSQL URL is invalid")
    if len(user.encode("utf-8")) > 63 or len(database.encode("utf-8")) > 63:
        raise SourcePostgresError("source PostgreSQL URL is invalid")
    return SourceUrl(address.compressed, port, user, database)


def validate_target_urls(values):
    pg_env = load_pg_env_tool()
    parsed = {}
    for name in ("SUB2API_TARGET_DATABASE_URL", "SUB2API_DATABASE_URL"):
        raw_url = values.get(name)
        if not raw_url:
            raise SourcePostgresError("private PostgreSQL environment is incomplete")
        try:
            parsed[name] = pg_env.libpq_environment({name: raw_url}, name)
        except Exception as error:
            raise SourcePostgresError("target PostgreSQL URL is invalid") from error
    target = parsed["SUB2API_TARGET_DATABASE_URL"]
    application = parsed["SUB2API_DATABASE_URL"]
    target_identity = (target.get("PGHOST"), target.get("PGPORT"), target.get("PGDATABASE"))
    application_identity = (
        application.get("PGHOST"),
        application.get("PGPORT"),
        application.get("PGDATABASE"),
    )
    if target_identity != application_identity or target_identity[:2] != (
        "127.0.0.1",
        "15432",
    ):
        raise SourcePostgresError("target PostgreSQL identity is invalid")


def parse_filtered_environment(raw, required, optional=()):
    allowed = set(required) | set(optional)
    values = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in allowed or key in values or not value:
            raise SourcePostgresError("container database metadata is invalid")
        values[key] = value
    if not set(required) <= set(values):
        raise SourcePostgresError("container database metadata is incomplete")
    return values


def inspect_container(name, expected_id, expected_running, *, runner):
    raw = decoded_stdout(
        runner(
            ["docker", "inspect", "--format", NETWORK_INSPECT_TEMPLATE, name],
            timeout=10,
            environment=docker_environment(),
        )
    )
    try:
        identity, container_name, running, network_json = raw.split("|", 3)
        networks = json.loads(network_json)
    except (ValueError, json.JSONDecodeError) as error:
        raise SourcePostgresError("container runtime metadata is invalid") from error
    if (
        identity != expected_id
        or container_name != f"/{name}"
        or running != ("true" if expected_running else "false")
        or not isinstance(networks, dict)
    ):
        raise SourcePostgresError("source container identity or state changed")
    return networks


def inspect_environment(name, template, required, optional, *, runner):
    result = runner(
        ["docker", "inspect", "--format", template, name],
        timeout=10,
        environment=docker_environment(),
    )
    return parse_filtered_environment(
        decoded_stdout(result), required=required, optional=optional
    )


def network_addresses(networks):
    result = {}
    for name, value in networks.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            raise SourcePostgresError("container network metadata is invalid")
        address = value.get("IPAddress")
        aliases = value.get("Aliases") or []
        if not isinstance(address, str) or not isinstance(aliases, list) or any(
            not isinstance(alias, str) for alias in aliases
        ):
            raise SourcePostgresError("container network metadata is invalid")
        result[name] = (address, frozenset(aliases))
    return result


def read_pg_control_identifier(postgres_id, *, runner):
    result = runner(
        [
            "docker",
            "exec",
            "--user",
            "postgres",
            postgres_id,
            "sh",
            "-ec",
            'LC_ALL=C exec pg_controldata "$PGDATA"',
        ],
        timeout=10,
        environment=docker_environment(),
    )
    match = PG_SYSTEM_ID_RE.search(decoded_stdout(result))
    if not match:
        raise SourcePostgresError("source PostgreSQL cluster identity is invalid")
    return match.group(1)


def validate_psql_arguments(arguments):
    seen = set()
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in PSQL_FLAG_OPTIONS or argument == "--field-separator=|":
            if argument in seen:
                raise SourcePostgresError("source PostgreSQL client option is duplicated")
            seen.add(argument)
            index += 1
            continue
        if argument in PSQL_FIXED_VALUE_OPTIONS:
            if argument in seen or index + 1 >= len(arguments):
                raise SourcePostgresError("source PostgreSQL client arguments are invalid")
            if arguments[index + 1] != PSQL_FIXED_VALUE_OPTIONS[argument]:
                raise SourcePostgresError("source PostgreSQL client option value is invalid")
            seen.add(argument)
            index += 2
            continue
        if argument == "--command":
            if argument in seen or index + 1 >= len(arguments):
                raise SourcePostgresError("source PostgreSQL client arguments are invalid")
            command = arguments[index + 1]
            if not command or "\\" in command or any(
                character in command for character in ("\x00", "\r", "\n")
            ):
                raise SourcePostgresError("source PostgreSQL command is invalid")
            seen.add(argument)
            index += 2
            continue
        raise SourcePostgresError("source PostgreSQL client option is not allowed")


def validate_pg_dump_arguments(arguments):
    seen = set()
    for argument in arguments:
        if argument in PG_DUMP_FLAG_OPTIONS or argument in PG_DUMP_FIXED_OPTIONS:
            if argument in seen:
                raise SourcePostgresError("source PostgreSQL client option is duplicated")
            seen.add(argument)
            continue
        if argument.startswith("--snapshot=") and PG_SNAPSHOT_RE.fullmatch(
            argument.removeprefix("--snapshot=")
        ):
            if "--snapshot" in seen:
                raise SourcePostgresError("source PostgreSQL client option is duplicated")
            seen.add("--snapshot")
            continue
        raise SourcePostgresError("source PostgreSQL client option is not allowed")


def docker_client_command(binding, client, arguments, pgoptions):
    if client not in {"psql", "pg_dump"}:
        raise SourcePostgresError("source PostgreSQL client is not allowed")
    if len(arguments) > 128 or any(
        not isinstance(argument, str)
        or "\x00" in argument
        or len(argument.encode("utf-8")) > 4096
        for argument in arguments
    ):
        raise SourcePostgresError("source PostgreSQL client arguments are invalid")
    if client == "psql":
        validate_psql_arguments(arguments)
    else:
        validate_pg_dump_arguments(arguments)
    if len(pgoptions.encode("utf-8")) > 512 or any(
        character in pgoptions for character in ("\x00", "\r", "\n")
    ):
        raise SourcePostgresError("source PostgreSQL options are invalid")
    command = ["docker", "exec", "--interactive", "--user", "postgres"]
    if pgoptions:
        command.extend(("--env", f"PGOPTIONS={pgoptions}"))
    command.extend(
        (
            binding.postgres_id,
            client,
            *arguments,
            "--host=/var/run/postgresql",
            "--port=5432",
            f"--username={binding.user}",
            f"--dbname={binding.database}",
        )
    )
    return command


def query_database_identity(source, postgres_id, pg_control_id, *, runner):
    provisional = SourceBinding(postgres_id, source.user, source.database, "", "", "")
    result = runner(
        docker_client_command(
            provisional,
            "psql",
            (
                "--no-psqlrc",
                "--quiet",
                "--tuples-only",
                "--no-align",
                "-v",
                "ON_ERROR_STOP=1",
                "--command",
                DATABASE_IDENTITY_SQL,
            ),
            IDENTITY_PGOPTIONS,
        ),
        timeout=10,
        environment=docker_environment(),
    )
    match = DATABASE_IDENTITY_RE.fullmatch(decoded_stdout(result))
    if not match or int(match.group(2)) > 4_294_967_295:
        raise SourcePostgresError("source PostgreSQL database identity is invalid")
    expected_database_name_hex = source.database.encode("utf-8").hex()
    if match.group(1) != pg_control_id or match.group(3) != expected_database_name_hex:
        raise SourcePostgresError("source PostgreSQL endpoint is not the exact container")
    return match.groups()


def verify_source_binding(options, *, runner=run_command):
    try:
        values = load_private_env_tool().read_private_environment(options.env_file)
    except Exception as error:
        raise SourcePostgresError("private PostgreSQL environment is invalid") from error
    source_raw = values.get("SUB2API_SOURCE_DATABASE_URL")
    if not source_raw:
        raise SourcePostgresError("private PostgreSQL environment is incomplete")
    source = parse_source_url(source_raw)
    validate_target_urls(values)

    postgres_networks = network_addresses(
        inspect_container(
            options.source_postgres_container,
            options.source_postgres_id,
            True,
            runner=runner,
        )
    )
    app_networks = network_addresses(
        inspect_container(
            options.source_app_container,
            options.source_app_id,
            options.source_app_state == "running",
            runner=runner,
        )
    )
    matching_networks = [
        name for name, (address, _aliases) in postgres_networks.items() if address == source.host
    ]
    if len(matching_networks) != 1 or matching_networks[0] not in app_networks:
        raise SourcePostgresError("source PostgreSQL is not on the exact shared network")
    shared_network = matching_networks[0]
    postgres_aliases = set(postgres_networks[shared_network][1])
    postgres_aliases.add(options.source_postgres_container)

    postgres_environment = inspect_environment(
        options.source_postgres_id,
        POSTGRES_ENV_TEMPLATE,
        required=("POSTGRES_USER",),
        optional=("POSTGRES_DB",),
        runner=runner,
    )
    postgres_database = postgres_environment.get(
        "POSTGRES_DB", postgres_environment["POSTGRES_USER"]
    )
    if (
        postgres_environment["POSTGRES_USER"] != source.user
        or postgres_database != source.database
    ):
        raise SourcePostgresError("source URL does not match the PostgreSQL container")

    app_environment = inspect_environment(
        options.source_app_id,
        APP_DATABASE_ENV_TEMPLATE,
        required=("DATABASE_HOST", "DATABASE_PORT", "DATABASE_DBNAME"),
        optional=(),
        runner=runner,
    )
    if (
        app_environment["DATABASE_HOST"] not in postgres_aliases | {source.host}
        or app_environment["DATABASE_PORT"] != "5432"
        or app_environment["DATABASE_DBNAME"] != source.database
    ):
        raise SourcePostgresError("legacy app database binding does not match the source")

    pg_control_id = read_pg_control_identifier(options.source_postgres_id, runner=runner)
    system_identifier, database_oid, database_name_hex = query_database_identity(
        source, options.source_postgres_id, pg_control_id, runner=runner
    )
    return SourceBinding(
        options.source_postgres_id,
        source.user,
        source.database,
        system_identifier,
        database_oid,
        database_name_hex,
    )


def pin_docker_socket():
    try:
        metadata = DOCKER_SOCKET.stat(follow_symlinks=False)
    except OSError as error:
        raise SourcePostgresError("local Docker socket is unavailable") from error
    if (
        DOCKER_SOCKET.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o002
    ):
        raise SourcePostgresError("local Docker socket is unsafe")


def parse_arguments(argv):
    parser = RedactedArgumentParser(add_help=True, allow_abbrev=False)
    parser.add_argument("--env-file", type=pathlib.Path, required=True)
    parser.add_argument("--source-app-container", required=True)
    parser.add_argument("--source-app-id", required=True)
    parser.add_argument("--source-postgres-container", required=True)
    parser.add_argument("--source-postgres-id", required=True)
    parser.add_argument("--source-app-state", choices=("running", "stopped"), required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)
    if (
        not options.env_file.is_absolute()
        or not CONTAINER_NAME_RE.fullmatch(options.source_app_container)
        or not CONTAINER_NAME_RE.fullmatch(options.source_postgres_container)
        or not CONTAINER_ID_RE.fullmatch(options.source_app_id)
        or not CONTAINER_ID_RE.fullmatch(options.source_postgres_id)
        or not options.command
        or options.command[0] not in {"identity", "psql", "pg_dump"}
        or (options.command[0] == "identity" and len(options.command) != 1)
    ):
        parser.error("source PostgreSQL arguments are invalid")
    return options


def sanitized_exec_environment():
    return docker_environment()


def main(argv=None):
    options = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        pin_docker_socket()
        binding = verify_source_binding(options)
        client = options.command[0]
        if client == "identity":
            print(
                "|".join(
                    (
                        binding.system_identifier,
                        binding.database_oid,
                        binding.database_name_hex,
                    )
                )
            )
            return 0
        command = docker_client_command(
            binding,
            client,
            tuple(options.command[1:]),
            os.environ.get("SUB2API_PGOPTIONS", ""),
        )
        os.execvpe(command[0], command, sanitized_exec_environment())
    except (OSError, SourcePostgresError, subprocess.SubprocessError):
        print("source PostgreSQL binding verification failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
