#!/usr/bin/python3 -I
"""Execute reviewed PostgreSQL clients against the active production database."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
from typing import NamedTuple


REPO_DIR = pathlib.Path(__file__).resolve().parents[1]
TRUSTED_RELEASE_PARENT = pathlib.Path("/opt")
TRUSTED_RELEASE_ROOT = TRUSTED_RELEASE_PARENT / "sub2api-gate-release"
TRUSTED_CONTROLLER = TRUSTED_RELEASE_ROOT / "deploy" / "active-postgres-exec.py"
PRIVATE_ENV_TOOL = REPO_DIR / "deploy" / "private_env.py"
PG_ENV_TOOL = REPO_DIR / "deploy" / "pg-env-exec.py"
SOURCE_HELPER = REPO_DIR / "deploy" / "source-postgres-exec.py"
RELEASE_POLICY = REPO_DIR / "deploy" / "release-policy.json"
COMPOSE_FILE = REPO_DIR / "docker-compose.yml"
DOCKER_BINARY = pathlib.Path("/usr/bin/docker")
DOCKER_SOCKET = pathlib.Path("/var/run/docker.sock")
APP_NAME = "sub2api"
POSTGRES_NAME = "sub2api-postgres"
EXPECTED_PROJECT = "sub2api-gate-release"
EXPECTED_DATA_MOUNT = pathlib.Path("/mnt/data/sub2api-gate/postgres")
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IMAGE_REFERENCE_RE = re.compile(r"postgres@sha256:[0-9a-f]{64}\Z")
POSTGRES_CONTRACT_TEMPLATE = (
    '{{.Image}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|'
    '{{.Config.Image}}|{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|'
    '{{.HostConfig.LogConfig.Type}}|'
    '{{index .Config.Labels "com.docker.compose.project"}}|'
    '{{index .Config.Labels "com.docker.compose.service"}}|'
    '{{index .Config.Labels "com.docker.compose.project.working_dir"}}|'
    '{{index .Config.Labels "com.docker.compose.project.config_files"}}|'
    "{{json .NetworkSettings.Ports}}"
)
APP_CONTRACT_TEMPLATE = (
    '{{if .State.Health}}{{.State.Health.Status}}{{end}}|{{.Config.User}}|'
    '{{.HostConfig.LogConfig.Type}}|'
    '{{index .Config.Labels "com.docker.compose.project"}}|'
    '{{index .Config.Labels "com.docker.compose.service"}}|'
    '{{index .Config.Labels "com.docker.compose.project.working_dir"}}|'
    '{{index .Config.Labels "com.docker.compose.project.config_files"}}|'
    "{{json .NetworkSettings.Ports}}"
)
MOUNTS_TEMPLATE = "{{json .Mounts}}"
APP_DATABASE_ENV_TEMPLATE = (
    '{{range .Config.Env}}{{ $parts := split . "=" }}'
    '{{if or (eq (index $parts 0) "DATABASE_HOST") '
    '(or (eq (index $parts 0) "DATABASE_PORT") '
    '(eq (index $parts 0) "DATABASE_DBNAME"))}}{{println .}}{{end}}{{end}}'
)


class ActivePostgresError(RuntimeError):
    pass


class ActiveBinding(NamedTuple):
    postgres_id: str
    user: str
    database: str
    system_identifier: str
    database_oid: str
    database_name_hex: str


class RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "active PostgreSQL command validation failed\n")


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ActivePostgresError("active PostgreSQL helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_private_env_tool():
    return load_module(PRIVATE_ENV_TOOL, "active_postgres_private_env")


def load_pg_env_tool():
    return load_module(PG_ENV_TOOL, "active_postgres_target_env")


def load_source_helper():
    return load_module(SOURCE_HELPER, "active_postgres_source_support")


def require_trusted_release_path(path, *, expects_directory):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise ActivePostgresError("trusted PostgreSQL release path is unavailable") from error
    if (
        not target.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or (expects_directory and not stat.S_ISDIR(metadata.st_mode))
        or (not expects_directory and not stat.S_ISREG(metadata.st_mode))
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ActivePostgresError("trusted PostgreSQL release path is unsafe")


def require_production_context():
    if os.geteuid() != 0:
        return
    try:
        source_path = pathlib.Path(__file__).resolve(strict=True)
    except OSError as error:
        raise ActivePostgresError("trusted PostgreSQL controller is unavailable") from error
    if REPO_DIR != TRUSTED_RELEASE_ROOT or source_path != TRUSTED_CONTROLLER:
        raise ActivePostgresError(
            "active PostgreSQL helper must run from the trusted production release tree"
        )
    for path, expects_directory in (
        (pathlib.Path("/"), True),
        (TRUSTED_RELEASE_PARENT, True),
        (TRUSTED_RELEASE_ROOT, True),
        (TRUSTED_RELEASE_ROOT / "deploy", True),
        (TRUSTED_CONTROLLER, False),
        (PRIVATE_ENV_TOOL, False),
        (PG_ENV_TOOL, False),
        (SOURCE_HELPER, False),
        (RELEASE_POLICY, False),
        (COMPOSE_FILE, False),
    ):
        require_trusted_release_path(path, expects_directory=expects_directory)


def source_support():
    return load_source_helper()


def docker_environment():
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "DOCKER_HOST": "unix:///var/run/docker.sock",
    }


def run_command(argv, *, timeout=10, environment=None):
    try:
        result = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            check=False,
            env=environment or docker_environment(),
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ActivePostgresError("active PostgreSQL metadata command failed") from error
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 64 * 1024:
        raise ActivePostgresError("active PostgreSQL metadata command failed")
    return result


def decoded_stdout(result):
    value = result.stdout
    if not isinstance(value, str) or len(value.encode("utf-8")) > 64 * 1024:
        raise ActivePostgresError("active PostgreSQL metadata is invalid")
    return value.strip()


def pin_docker_socket():
    try:
        metadata = DOCKER_SOCKET.stat(follow_symlinks=False)
    except OSError as error:
        raise ActivePostgresError("local Docker socket is unavailable") from error
    if (
        DOCKER_SOCKET.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o002
    ):
        raise ActivePostgresError("local Docker socket is unsafe")


def reviewed_postgres_image():
    try:
        raw = RELEASE_POLICY.read_bytes()
        if len(raw) > 64 * 1024:
            raise ValueError("oversized")
        policy = json.loads(raw.decode("ascii"))
        image = policy["postgres"]["image"]
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
        raise ActivePostgresError("PostgreSQL release policy is invalid") from error
    if not isinstance(image, str) or not IMAGE_REFERENCE_RE.fullmatch(image):
        raise ActivePostgresError("PostgreSQL release policy is invalid")
    return image


def inspect_postgres_contract(postgres_id, *, runner):
    result = runner(
        [
            str(DOCKER_BINARY),
            "inspect",
            "--format",
            POSTGRES_CONTRACT_TEMPLATE,
            postgres_id,
        ],
        timeout=10,
        environment=docker_environment(),
    )
    fields = decoded_stdout(result).split("|", 10)
    if len(fields) != 11:
        raise ActivePostgresError("active PostgreSQL runtime contract is invalid")
    (
        running_image_id,
        health,
        configured_image,
        user,
        read_only,
        log_driver,
        project,
        service,
        working_directory,
        config_files,
        ports_raw,
    ) = fields
    expected_image = reviewed_postgres_image()
    image_result = runner(
        [str(DOCKER_BINARY), "image", "inspect", "--format", "{{.Id}}", expected_image],
        timeout=10,
        environment=docker_environment(),
    )
    expected_image_id = decoded_stdout(image_result)
    try:
        ports = json.loads(ports_raw)
    except json.JSONDecodeError as error:
        raise ActivePostgresError("active PostgreSQL port contract is invalid") from error
    if (
        not IMAGE_ID_RE.fullmatch(running_image_id)
        or not IMAGE_ID_RE.fullmatch(expected_image_id)
        or running_image_id != expected_image_id
        or health != "healthy"
        or configured_image != expected_image
        or user != "70:70"
        or read_only != "true"
        or log_driver != "none"
        or project != EXPECTED_PROJECT
        or service != "postgres"
        or working_directory != str(TRUSTED_RELEASE_ROOT)
        or config_files != str(TRUSTED_RELEASE_ROOT / "docker-compose.yml")
        or ports != {"5432/tcp": None}
    ):
        raise ActivePostgresError("active PostgreSQL runtime contract is invalid")


def inspect_app_contract(app_id, *, runner):
    result = runner(
        [str(DOCKER_BINARY), "inspect", "--format", APP_CONTRACT_TEMPLATE, app_id],
        timeout=10,
        environment=docker_environment(),
    )
    fields = decoded_stdout(result).split("|", 7)
    if len(fields) != 8:
        raise ActivePostgresError("active Sub2API runtime contract is invalid")
    health, user, log_driver, project, service, working_directory, config_files, ports_raw = (
        fields
    )
    try:
        ports = json.loads(ports_raw)
    except json.JSONDecodeError as error:
        raise ActivePostgresError("active Sub2API port contract is invalid") from error
    if (
        health != "healthy"
        or user != "1000:1000"
        or log_driver != "none"
        or project != EXPECTED_PROJECT
        or service != "sub2api"
        or working_directory != str(TRUSTED_RELEASE_ROOT)
        or config_files != str(TRUSTED_RELEASE_ROOT / "docker-compose.yml")
        or ports
        != {
            "8080/tcp": [
                {"HostIp": "127.0.0.1", "HostPort": "8080"}
            ]
        }
    ):
        raise ActivePostgresError("active Sub2API runtime contract is invalid")


def verify_postgres_mount(postgres_id, *, runner):
    result = runner(
        [str(DOCKER_BINARY), "inspect", "--format", MOUNTS_TEMPLATE, postgres_id],
        timeout=10,
        environment=docker_environment(),
    )
    try:
        mounts = json.loads(decoded_stdout(result))
    except json.JSONDecodeError as error:
        raise ActivePostgresError("active PostgreSQL mount contract is invalid") from error
    if (
        not isinstance(mounts, list)
        or len(mounts) != 1
        or not isinstance(mounts[0], dict)
        or mounts[0].get("Type") != "bind"
        or mounts[0].get("Source") != str(EXPECTED_DATA_MOUNT)
        or mounts[0].get("Destination") != "/var/lib/postgresql"
        or mounts[0].get("RW") is not True
    ):
        raise ActivePostgresError("active PostgreSQL mount contract is invalid")


def target_environment(values):
    pg_env = load_pg_env_tool()
    parsed = {}
    for name in ("SUB2API_TARGET_DATABASE_URL", "SUB2API_DATABASE_URL"):
        raw_url = values.get(name)
        if not raw_url:
            raise ActivePostgresError("private PostgreSQL environment is incomplete")
        try:
            parsed[name] = pg_env.libpq_environment({name: raw_url}, name)
        except Exception as error:
            raise ActivePostgresError("target PostgreSQL URL is invalid") from error
    target = parsed["SUB2API_TARGET_DATABASE_URL"]
    application = parsed["SUB2API_DATABASE_URL"]
    target_identity = (
        target.get("PGHOST"),
        target.get("PGPORT"),
        target.get("PGDATABASE"),
    )
    application_identity = (
        application.get("PGHOST"),
        application.get("PGPORT"),
        application.get("PGDATABASE"),
    )
    if (
        target_identity != application_identity
        or target_identity[:2] != ("127.0.0.1", "15432")
        or not target.get("PGUSER")
    ):
        raise ActivePostgresError("target PostgreSQL identity is invalid")
    return target


def verify_active_binding(options, *, runner=run_command):
    support = source_support()
    try:
        private_values = load_private_env_tool().read_private_environment(options.env_file)
    except Exception as error:
        raise ActivePostgresError("private PostgreSQL environment is invalid") from error
    target = target_environment(private_values)

    try:
        postgres_networks = support.network_addresses(
            support.inspect_container(
                POSTGRES_NAME, options.postgres_id, True, runner=runner
            )
        )
        app_networks = support.network_addresses(
            support.inspect_container(APP_NAME, options.app_id, True, runner=runner)
        )
    except Exception as error:
        raise ActivePostgresError("active container identity is invalid") from error
    if len(postgres_networks) != 1:
        raise ActivePostgresError("active PostgreSQL network contract is invalid")
    shared_network = next(iter(postgres_networks))
    if shared_network not in app_networks:
        raise ActivePostgresError("active PostgreSQL network contract is invalid")

    inspect_postgres_contract(options.postgres_id, runner=runner)
    inspect_app_contract(options.app_id, runner=runner)
    verify_postgres_mount(options.postgres_id, runner=runner)
    try:
        postgres_environment = support.inspect_environment(
            options.postgres_id,
            support.POSTGRES_ENV_TEMPLATE,
            required=("POSTGRES_USER",),
            optional=("POSTGRES_DB",),
            runner=runner,
        )
        app_environment = support.inspect_environment(
            options.app_id,
            APP_DATABASE_ENV_TEMPLATE,
            required=("DATABASE_HOST", "DATABASE_PORT", "DATABASE_DBNAME"),
            optional=(),
            runner=runner,
        )
    except Exception as error:
        raise ActivePostgresError("active database metadata is invalid") from error
    database = postgres_environment.get(
        "POSTGRES_DB", postgres_environment["POSTGRES_USER"]
    )
    aliases = set(postgres_networks[shared_network][1])
    aliases.add(POSTGRES_NAME)
    if (
        target["PGUSER"] != postgres_environment["POSTGRES_USER"]
        or target["PGDATABASE"] != database
        or app_environment["DATABASE_HOST"] not in aliases
        or app_environment["DATABASE_PORT"] != "5432"
        or app_environment["DATABASE_DBNAME"] != database
    ):
        raise ActivePostgresError("active database binding is invalid")

    try:
        pg_control_id = support.read_pg_control_identifier(
            options.postgres_id, runner=runner
        )
        endpoint = support.SourceUrl("127.0.0.1", 5432, target["PGUSER"], database)
        system_identifier, database_oid, database_name_hex = (
            support.query_database_identity(
                endpoint, options.postgres_id, pg_control_id, runner=runner
            )
        )
    except Exception as error:
        raise ActivePostgresError("active PostgreSQL identity is invalid") from error
    return ActiveBinding(
        options.postgres_id,
        target["PGUSER"],
        database,
        system_identifier,
        database_oid,
        database_name_hex,
    )


def active_client_command(binding, arguments, pgoptions):
    try:
        return source_support().docker_client_command(
            binding, "psql", tuple(arguments), pgoptions
        )
    except Exception as error:
        raise ActivePostgresError("active PostgreSQL client arguments are invalid") from error


def parse_arguments(argv):
    parser = RedactedArgumentParser(add_help=True, allow_abbrev=False)
    parser.add_argument("--env-file", type=pathlib.Path, required=True)
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--postgres-id", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)
    if (
        not options.env_file.is_absolute()
        or not CONTAINER_ID_RE.fullmatch(options.app_id)
        or not CONTAINER_ID_RE.fullmatch(options.postgres_id)
        or not options.command
        or options.command[0] not in {"identity", "psql"}
        or (options.command[0] == "identity" and len(options.command) != 1)
    ):
        parser.error("active PostgreSQL arguments are invalid")
    return options


def main(argv=None):
    options = parse_arguments(sys.argv[1:] if argv is None else argv)
    try:
        require_production_context()
        pin_docker_socket()
        binding = verify_active_binding(options)
        if options.command[0] == "identity":
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
        command = active_client_command(
            binding,
            tuple(options.command[1:]),
            os.environ.get("SUB2API_PGOPTIONS", ""),
        )
        os.execve(str(DOCKER_BINARY), command, docker_environment())
    except (OSError, ActivePostgresError, subprocess.SubprocessError):
        print("active PostgreSQL binding verification failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
