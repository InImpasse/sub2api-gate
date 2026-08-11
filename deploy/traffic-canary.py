#!/usr/bin/env python3
"""Start and attest the sanitized, traffic-capable Sub2API target."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import time


REPO_DIR = pathlib.Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO_DIR / "docker-compose.traffic-canary.yml"
DATA_ROOT = pathlib.Path("/mnt/data/sub2api-gate")
DOCKER_SOCKET = pathlib.Path("/var/run/docker.sock")
PROFILE = "traffic-canary"
PROJECT = "sub2api-gate-traffic-canary"

TARGET_APP = "sub2api-traffic-canary"
TARGET_POSTGRES = "sub2api-traffic-canary-postgres"
TARGET_REDIS = "sub2api-traffic-canary-redis"
TARGET_NAMES = (TARGET_APP, TARGET_POSTGRES, TARGET_REDIS)

SUB2API_IMAGE = (
    "weishaw/sub2api@sha256:"
    "0ffc0202507c3510a696feab92e99faac28e72624ece8f40484b157ba68547b0"
)
POSTGRES_IMAGE = (
    "postgres@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
REDIS_IMAGE = (
    "redis@sha256:"
    "9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005"
)
RUNTIME_IMAGES = (SUB2API_IMAGE, POSTGRES_IMAGE, REDIS_IMAGE)
CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PG_SYSTEM_ID_RE = re.compile(r"^Database system identifier:\s*([0-9]{10,24})\s*$", re.M)
REDIS_RUN_ID_RE = re.compile(r"^run_id:([0-9a-f]{40})\r?$", re.M)
DEPENDENCY_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")
POSTGRES_RUNTIME_LOG_GATE = REPO_DIR / "deploy" / "verify-postgres-runtime-logging.sql"


class CanaryError(RuntimeError):
    pass


class UsageError(CanaryError):
    pass


def run_command(
    command,
    *,
    input_bytes=None,
    timeout=30,
    allow_failure=False,
    environment=None,
):
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CanaryError("required local command failed") from error
    if result.returncode and not allow_failure:
        raise CanaryError("required local command returned a failure")
    return result


def decoded_stdout(result):
    try:
        return result.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise CanaryError("local command returned invalid text") from error


def require_local_runtime_images(*, runner=run_command):
    image_ids = {}
    for reference in RUNTIME_IMAGES:
        result = runner(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}|{{.Os}}|{{.Architecture}}|{{json .RepoDigests}}",
                reference,
            ],
            timeout=15,
        )
        fields = decoded_stdout(result).split("|", 3)
        if len(fields) != 4:
            raise CanaryError("local runtime image metadata is invalid")
        image_id, operating_system, architecture, repo_digests_json = fields
        try:
            repo_digests = json.loads(repo_digests_json)
        except json.JSONDecodeError as error:
            raise CanaryError("local runtime image RepoDigests are invalid") from error
        if (
            not IMAGE_ID_RE.fullmatch(image_id)
            or operating_system != "linux"
            or architecture not in {"amd64", "arm64"}
            or not isinstance(repo_digests, list)
            or reference not in repo_digests
            or any(not isinstance(value, str) for value in repo_digests)
        ):
            raise CanaryError("local runtime image does not match the reviewed digest")
        image_ids[reference] = image_id
    if len(set(image_ids.values())) != len(RUNTIME_IMAGES):
        raise CanaryError("reviewed runtime images must have distinct local identities")
    return image_ids


def check_compose_contract():
    try:
        source = COMPOSE_FILE.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CanaryError("traffic canary Compose file is unavailable") from error

    required = (
        "name: sub2api-gate-traffic-canary",
        "SUB2API_DATA_ROOT must be /mnt/data/sub2api-gate",
        SUB2API_IMAGE,
        POSTGRES_IMAGE,
        REDIS_IMAGE,
        'container_name: sub2api-traffic-canary',
        'container_name: sub2api-traffic-canary-postgres',
        'container_name: sub2api-traffic-canary-redis',
        'sub2api-gate.canary-purpose: migrated-target-traffic-only',
        '"127.0.0.1:8081:8080"',
        "source: /mnt/data/sub2api-gate/app",
        "source: /mnt/data/sub2api-gate/postgres",
        "target: /var/lib/postgresql",
        "PGDATA: /var/lib/postgresql/18/docker",
        "source: /mnt/data/sub2api-gate/redis/users.acl",
        "mem_limit: 256m",
        "--maxmemory",
        "128mb",
        "--maxmemory-policy",
        "noeviction",
        'AUTO_SETUP: "false"',
        "DATABASE_USER: sub2api_app",
        'LOG_OUTPUT_TO_FILE: "false"',
        'GATEWAY_LOG_UPSTREAM_ERROR_BODY: "false"',
        'RISK_CONTROL_ENABLED: "false"',
        'IMAGE_STORAGE_ENABLED: "false"',
        "logging_collector=off",
        "log_destination=stderr",
        "log_statement=none",
        "log_min_error_statement=panic",
        "log_parameter_max_length_on_error=0",
        "log_min_duration_sample=-1",
        "log_transaction_sample_rate=0",
        "internal: true",
    )
    if any(value not in source for value in required):
        raise CanaryError("traffic canary Compose contract is incomplete")
    if source.count('profiles: ["traffic-canary"]') != 3:
        raise CanaryError("traffic canary services must remain profile-gated")
    if source.count('driver: "none"') != 3:
        raise CanaryError("every traffic canary service must discard Docker logs")
    if source.count("pull_policy: never") != 3:
        raise CanaryError("traffic canary images must be preloaded and never pulled at runtime")
    if source.count("core:\n        soft: 0\n        hard: 0") != 3:
        raise CanaryError("every traffic canary service must disable core dumps")
    if source.count("create_host_path: false") != 3:
        raise CanaryError("traffic canary bind mounts must fail when missing")
    for forbidden in (
        'AUTO_SETUP: "true"',
        "sub2api-sync:",
        "3021:3021",
        "3022:3021",
        "external: true",
        "./postgres_data",
        "target: /var/lib/postgresql/data",
        "PGDATA: /var/lib/postgresql/data",
        "./redis_data",
        "./data:/app/data",
    ):
        if forbidden in source:
            raise CanaryError("traffic canary Compose contains a forbidden path")


def parse_private_env(path):
    try:
        file_stat = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CanaryError("private environment file is unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(file_stat.st_mode):
        raise CanaryError("private environment file must be a regular non-symlink file")
    if stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise CanaryError("private environment file must use mode 0600")
    values = {}
    try:
        lines = resolved.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CanaryError("private environment file could not be read") from error
    for raw_line in lines:
        line = raw_line.rstrip("\r")
        if not line or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if (
            not separator
            or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
            or key in values
            or key.startswith("DOCKER_")
            or key.startswith("COMPOSE_")
        ):
            raise CanaryError("private environment file is invalid")
        values[key] = value
    if values.get("SUB2API_DATA_ROOT") != str(DATA_ROOT):
        raise CanaryError("SUB2API_DATA_ROOT must be /mnt/data/sub2api-gate")
    return resolved, frozenset(values)


def require_private_config(path, label):
    try:
        file_stat = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CanaryError(f"{label} is unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(file_stat.st_mode):
        raise CanaryError(f"{label} must be a regular non-symlink file")
    if stat.S_IMODE(file_stat.st_mode) != 0o600:
        raise CanaryError(f"{label} must use mode 0600")
    return resolved


def require_path(path, *, kind, uid, gid, mode):
    try:
        path_stat = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CanaryError("required migrated-target path is unavailable") from error
    if path.is_symlink() or resolved != path:
        raise CanaryError("required migrated-target path is unsafe")
    if kind == "directory" and not stat.S_ISDIR(path_stat.st_mode):
        raise CanaryError("required migrated-target directory is invalid")
    if kind == "file" and not stat.S_ISREG(path_stat.st_mode):
        raise CanaryError("required migrated-target file is invalid")
    if (path_stat.st_uid, path_stat.st_gid) != (uid, gid):
        raise CanaryError("required migrated-target path has unsafe ownership")
    if stat.S_IMODE(path_stat.st_mode) != mode:
        raise CanaryError("required migrated-target path has unsafe permissions")
    return path_stat


def require_private_regular_file(path, *, uid, gid, maximum_mode=0o600):
    try:
        path_stat = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CanaryError("required migrated-target file is unavailable") from error
    if path.is_symlink() or resolved != path or not stat.S_ISREG(path_stat.st_mode):
        raise CanaryError("required migrated-target file is unsafe")
    if (path_stat.st_uid, path_stat.st_gid) != (uid, gid):
        raise CanaryError("required migrated-target file has unsafe ownership")
    if stat.S_IMODE(path_stat.st_mode) & ~maximum_mode:
        raise CanaryError("required migrated-target file has unsafe permissions")
    return path_stat


def validate_storage():
    require_path(DATA_ROOT, kind="directory", uid=0, gid=0, mode=0o700)
    app = DATA_ROOT / "app"
    postgres = DATA_ROOT / "postgres"
    redis = DATA_ROOT / "redis"
    require_path(app, kind="directory", uid=1000, gid=1000, mode=0o700)
    require_path(postgres, kind="directory", uid=70, gid=70, mode=0o700)
    require_path(redis, kind="directory", uid=999, gid=1000, mode=0o700)

    marker = app / ".installed"
    require_path(marker, kind="file", uid=1000, gid=1000, mode=0o400)
    try:
        marker_value = marker.read_bytes()
    except OSError as error:
        raise CanaryError("app migration marker could not be read") from error
    if marker_value != b"installed_by=sub2api-gate\n":
        raise CanaryError("app migration marker is not the reviewed marker")
    app_entries = {entry.name for entry in app.iterdir()}
    if not app_entries <= {".installed", "model_pricing.json"}:
        raise CanaryError("target app directory was not fresh before canary startup")
    pricing = app / "model_pricing.json"
    if pricing.exists():
        pricing_stat = require_path(
            pricing, kind="file", uid=1000, gid=1000, mode=0o600
        )
        if not 0 < pricing_stat.st_size <= 8 * 1024 * 1024:
            raise CanaryError("target model pricing metadata has an invalid size")

    cluster = postgres / "18" / "docker"
    require_path(postgres / "18", kind="directory", uid=70, gid=70, mode=0o755)
    require_path(cluster, kind="directory", uid=70, gid=70, mode=0o700)
    pg_version = cluster / "PG_VERSION"
    require_private_regular_file(pg_version, uid=70, gid=70)
    try:
        version_value = pg_version.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise CanaryError("target PostgreSQL version marker could not be read") from error
    if version_value != "18":
        raise CanaryError("target PostgreSQL data directory is not version 18")
    require_private_regular_file(cluster / "global" / "pg_control", uid=70, gid=70)
    pg_wal = cluster / "pg_wal"
    try:
        pg_wal_stat = pg_wal.stat(follow_symlinks=False)
    except OSError as error:
        raise CanaryError("target PostgreSQL WAL directory is unavailable") from error
    if pg_wal.is_symlink() or not stat.S_ISDIR(pg_wal_stat.st_mode):
        raise CanaryError("target PostgreSQL WAL directory must remain inside the target")

    walk_errors = []

    def record_walk_error(error):
        walk_errors.append(error)

    for directory, directory_names, file_names in os.walk(
        DATA_ROOT, topdown=True, onerror=record_walk_error, followlinks=False
    ):
        relative_directory = pathlib.Path(directory).relative_to(DATA_ROOT)
        lowered_parents = {part.lower() for part in relative_directory.parts}
        for name in directory_names:
            candidate = pathlib.Path(directory) / name
            if candidate.is_symlink() and name.lower() in {
                "log",
                "pg_log",
                "postgresql-log",
                "postgresql-logs",
                "postgresql_log",
            }:
                raise CanaryError("target storage contains PostgreSQL log artifacts")
        for name in file_names:
            lowered = name.lower()
            if (
                lowered == "current_logfiles"
                or lowered.endswith(".log")
                or (
                    lowered.startswith("postgresql-")
                    and lowered.endswith((".csv", ".json"))
                )
                or lowered_parents
                & {
                    "log",
                    "pg_log",
                    "postgresql-log",
                    "postgresql-logs",
                    "postgresql_log",
                }
            ):
                raise CanaryError("target storage contains PostgreSQL log artifacts")
    if walk_errors:
        raise CanaryError("target storage log residue could not be inspected")

    acl = redis / "users.acl"
    require_path(acl, kind="file", uid=999, gid=1000, mode=0o400)
    try:
        acl_text = acl.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise CanaryError("target Redis ACL could not be read") from error
    if (
        len(acl_text.splitlines()) != 1
        or not re.match(r"^user default reset on #[0-9a-f]{64}(?: |$)", acl_text)
        or " nopass" in acl_text
        or " >" in acl_text
        or "resetkeys" not in acl_text
        or "resetchannels" not in acl_text
        or "+@all" not in acl_text
        or "-@admin" not in acl_text
        or "-@dangerous" not in acl_text
    ):
        raise CanaryError("target Redis ACL is not the reviewed hashed runtime ACL")


def validate_container_name(name, label):
    if not CONTAINER_NAME_RE.fullmatch(name) or name in TARGET_NAMES:
        raise UsageError(f"{label} is invalid or aliases the migrated target")


def docker_inspect(container, template, *, runner=run_command):
    result = runner(
        ["docker", "inspect", "--format", template, container],
        timeout=10,
    )
    return decoded_stdout(result)


def docker_inspect_json(container, template, *, runner=run_command):
    raw = docker_inspect(container, template, runner=runner)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise CanaryError("Docker returned invalid inspection metadata") from error


def container_exists(container, *, runner=run_command):
    result = runner(
        ["docker", "inspect", "--format", "{{.Id}}", container],
        timeout=10,
        allow_failure=True,
    )
    return result.returncode == 0


def container_id(container, *, runner=run_command):
    value = docker_inspect(container, "{{.Id}}", runner=runner)
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise CanaryError("Docker returned an invalid container identity")
    return value


def require_running(container, *, require_healthy=False, runner=run_command):
    value = docker_inspect(
        container,
        "{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
        runner=runner,
    )
    running, separator, health = value.partition("|")
    if not separator or running != "true":
        raise CanaryError("required container is not running")
    if require_healthy and health != "healthy":
        raise CanaryError("migrated-target container is not healthy")


def wait_healthy(container, *, runner=run_command, timeout=120):
    deadline = time.monotonic() + timeout
    while True:
        try:
            require_running(container, require_healthy=True, runner=runner)
            return
        except CanaryError:
            if time.monotonic() >= deadline:
                raise CanaryError("migrated-target container did not become healthy")
            time.sleep(2)


def require_port(container, host_port, *, runner=run_command):
    ports = docker_inspect_json(
        container, "{{json .NetworkSettings.Ports}}", runner=runner
    )
    expected = [{"HostIp": "127.0.0.1", "HostPort": str(host_port)}]
    if ports.get("8080/tcp") != expected:
        raise CanaryError("Sub2API container is not bound to the reviewed loopback port")
    if any(bindings for port, bindings in ports.items() if port != "8080/tcp"):
        raise CanaryError("Sub2API container exposes an unreviewed port")


def require_no_ports(container, *, runner=run_command):
    ports = docker_inspect_json(
        container, "{{json .NetworkSettings.Ports}}", runner=runner
    )
    if any(bindings for bindings in ports.values()):
        raise CanaryError("target data service exposes a host port")


def mount_sources(container, *, runner=run_command):
    mounts = docker_inspect_json(container, "{{json .Mounts}}", runner=runner)
    if not isinstance(mounts, list):
        raise CanaryError("Docker returned invalid mount metadata")
    return mounts


def runtime_dependency_hosts(container, *, runner=run_command):
    result = runner(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-ec",
            'printf \'database=%s\\nredis=%s\\n\' "${DATABASE_HOST-}" "${REDIS_HOST-}"',
        ],
        timeout=10,
    )
    lines = decoded_stdout(result).splitlines()
    expected = ("database", "redis")
    values = {}
    if len(lines) != len(expected):
        raise CanaryError("legacy Sub2API dependency hosts could not be verified")
    for line, name in zip(lines, expected):
        prefix = f"{name}="
        value = line.removeprefix(prefix)
        if not line.startswith(prefix) or not DEPENDENCY_HOST_RE.fullmatch(value):
            raise CanaryError("legacy Sub2API dependency hosts could not be verified")
        values[name] = value
    return values


def network_attachments(container, *, runner=run_command):
    networks = docker_inspect_json(
        container,
        "{{json .NetworkSettings.Networks}}",
        runner=runner,
    )
    if not isinstance(networks, dict) or not networks:
        raise CanaryError("legacy Docker network membership could not be verified")
    for name, attachment in networks.items():
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(attachment, dict)
            or not re.fullmatch(r"[0-9a-f]{64}", str(attachment.get("NetworkID", "")))
        ):
            raise CanaryError("legacy Docker network membership could not be verified")
    return networks


def dependency_network_names(container, attachment):
    names = {container.lstrip("/")}
    for field in ("Aliases", "DNSNames"):
        values = attachment.get(field) or []
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise CanaryError("legacy Docker network aliases could not be verified")
        names.update(value for value in values if DEPENDENCY_HOST_RE.fullmatch(value))
    for field in ("IPAddress", "GlobalIPv6Address"):
        value = attachment.get(field)
        if isinstance(value, str) and DEPENDENCY_HOST_RE.fullmatch(value):
            names.add(value)
    return names


def require_legacy_dependency(app, dependency, configured_host, label, *, runner=run_command):
    app_networks = network_attachments(app, runner=runner)
    dependency_networks = network_attachments(dependency, runner=runner)
    shared_networks = set(app_networks).intersection(dependency_networks)
    if not shared_networks:
        raise CanaryError(f"legacy Sub2API does not share a Docker network with {label}")

    for network_name in shared_networks:
        attachment = dependency_networks[network_name]
        if configured_host in dependency_network_names(dependency, attachment):
            return
    raise CanaryError(f"legacy Sub2API {label} host does not identify the supplied container")


def require_exact_bind(container, source, destination, read_only, *, runner=run_command):
    binds = [item for item in mount_sources(container, runner=runner) if item.get("Type") == "bind"]
    expected = {
        "Source": source,
        "Destination": destination,
        "RW": not read_only,
    }
    matches = [
        item
        for item in binds
        if all(item.get(key) == value for key, value in expected.items())
    ]
    if len(binds) != 1 or len(matches) != 1:
        raise CanaryError("target container bind mount is not the reviewed migrated path")


def require_runtime_hardening(container, image, user, *, runner=run_command):
    if docker_inspect(container, "{{.Config.Image}}", runner=runner) != image:
        raise CanaryError("target container does not use the reviewed image digest")
    if docker_inspect(container, "{{.Config.User}}", runner=runner) != user:
        raise CanaryError("target container does not use the reviewed runtime identity")
    if docker_inspect(container, "{{.HostConfig.ReadonlyRootfs}}", runner=runner) != "true":
        raise CanaryError("target container root filesystem is writable")
    if docker_inspect(container, "{{.HostConfig.LogConfig.Type}}", runner=runner) != "none":
        raise CanaryError("target container Docker logging is enabled")
    cap_drop = docker_inspect_json(container, "{{json .HostConfig.CapDrop}}", runner=runner)
    if "ALL" not in (cap_drop or []):
        raise CanaryError("target container has not dropped Linux capabilities")
    security = docker_inspect_json(
        container, "{{json .HostConfig.SecurityOpt}}", runner=runner
    )
    if "no-new-privileges:true" not in (security or []):
        raise CanaryError("target container lacks no-new-privileges")
    ulimits = docker_inspect_json(
        container, "{{json .HostConfig.Ulimits}}", runner=runner
    )
    if not any(
        item.get("Name") == "core"
        and item.get("Soft") == 0
        and item.get("Hard") == 0
        for item in (ulimits or [])
    ):
        raise CanaryError("target container core dumps are not disabled")


def require_project_members(*, runner=run_command):
    members = project_members(runner=runner)
    if members != set(TARGET_NAMES):
        raise CanaryError("traffic canary Compose project has unexpected members")


def project_members(*, runner=run_command):
    result = runner(
        [
            "docker",
            "ps",
            "--all",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
            "--format",
            "{{.Names}}",
        ],
        timeout=10,
    )
    return {line for line in decoded_stdout(result).splitlines() if line}


def require_no_active_swap():
    try:
        lines = pathlib.Path("/proc/swaps").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise CanaryError("host swap state could not be verified") from error
    if any(line.strip() for line in lines[1:]):
        raise CanaryError("active host swap could persist traffic canary memory")


def pin_local_docker_socket():
    try:
        socket_stat = DOCKER_SOCKET.stat(follow_symlinks=False)
    except OSError as error:
        raise CanaryError("local Docker socket is unavailable") from error
    if (
        DOCKER_SOCKET.is_symlink()
        or not stat.S_ISSOCK(socket_stat.st_mode)
        or socket_stat.st_uid != 0
        or stat.S_IMODE(socket_stat.st_mode) & 0o002
    ):
        raise CanaryError("local Docker socket is unsafe")
    for key in tuple(os.environ):
        if key.startswith("DOCKER_"):
            os.environ.pop(key, None)
    os.environ["DOCKER_HOST"] = "unix:///var/run/docker.sock"


def require_labels(container, service, *, runner=run_command):
    labels = docker_inspect_json(container, "{{json .Config.Labels}}", runner=runner)
    if (
        labels.get("com.docker.compose.project") != PROJECT
        or labels.get("com.docker.compose.service") != service
    ):
        raise CanaryError("target container does not belong to the reviewed Compose service")


def pg_system_identifier(container, *, runner=run_command):
    result = runner(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-ec",
            'LC_ALL=C exec pg_controldata "$PGDATA"',
        ],
        timeout=10,
    )
    match = PG_SYSTEM_ID_RE.search(decoded_stdout(result))
    if not match:
        raise CanaryError("PostgreSQL cluster identity could not be verified")
    return match.group(1)


def redis_run_identifier(container, *, runner=run_command):
    result = runner(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-ec",
            "exec redis-cli --user default --raw INFO server",
        ],
        timeout=10,
    )
    match = REDIS_RUN_ID_RE.search(decoded_stdout(result))
    if not match:
        raise CanaryError("Redis runtime identity could not be verified")
    return match.group(1)


def require_binary_versions(*, runner=run_command):
    app = decoded_stdout(
        runner(["docker", "exec", TARGET_APP, "/app/sub2api", "--version"], timeout=10)
    )
    if not app.startswith("Sub2API 0.1.171"):
        raise CanaryError("target Sub2API binary is not version 0.1.171")
    postgres = decoded_stdout(
        runner(["docker", "exec", TARGET_POSTGRES, "postgres", "--version"], timeout=10)
    )
    if "PostgreSQL) 18." not in postgres:
        raise CanaryError("target PostgreSQL binary is not major version 18")
    redis = decoded_stdout(
        runner(["docker", "exec", TARGET_REDIS, "redis-server", "--version"], timeout=10)
    )
    if "v=8.8.0" not in redis:
        raise CanaryError("target Redis binary is not version 8.8.0")


def require_redis_volatile(*, require_empty, runner=run_command):
    command = docker_inspect_json(TARGET_REDIS, "{{json .Config.Cmd}}", runner=runner)
    try:
        appendonly = command[command.index("--appendonly") + 1]
        save = command[command.index("--save") + 1]
        maxmemory = command[command.index("--maxmemory") + 1]
        maxmemory_policy = command[command.index("--maxmemory-policy") + 1]
    except (AttributeError, ValueError, IndexError) as error:
        raise CanaryError("target Redis command is not the reviewed volatile command") from error
    if (
        appendonly != "no"
        or save != ""
        or maxmemory != "128mb"
        or maxmemory_policy != "noeviction"
    ):
        raise CanaryError(
            "target Redis persistence and memory policy must match the reviewed command"
        )
    tmpfs = docker_inspect_json(TARGET_REDIS, "{{json .HostConfig.Tmpfs}}", runner=runner)
    if not isinstance(tmpfs, dict) or "/data" not in tmpfs or "/tmp" not in tmpfs:
        raise CanaryError("target Redis data is not on reviewed tmpfs storage")
    if require_empty:
        size = decoded_stdout(
            runner(
                [
                    "docker",
                    "exec",
                    TARGET_REDIS,
                    "redis-cli",
                    "--user",
                    "default",
                    "--raw",
                    "DBSIZE",
                ],
                timeout=10,
            )
        )
        if size != "0":
            raise CanaryError("target volatile Redis was not empty before app startup")


def run_postgres_gate(path, *, runner=run_command):
    try:
        sql = path.read_bytes()
    except OSError as error:
        raise CanaryError("PostgreSQL privacy gate is unavailable") from error
    runner(
        [
            "docker",
            "exec",
            "-i",
            TARGET_POSTGRES,
            "sh",
            "-ec",
            'PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=30000" '
            'exec psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 '
            '-U "$POSTGRES_USER" -d "$POSTGRES_DB"',
        ],
        input_bytes=sql,
        timeout=40,
    )


def require_app_role(*, runner=run_command):
    query = (
        "WITH app AS (SELECT oid FROM pg_roles WHERE rolname='sub2api_app') "
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='sub2api_app' "
        "AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole "
        "AND NOT rolreplication AND NOT rolbypassrls AND NOT rolinherit) "
        "AND NOT EXISTS (SELECT 1 FROM pg_auth_members m JOIN app ON m.member=app.oid) "
        "AND NOT EXISTS (SELECT 1 FROM pg_database d JOIN app ON d.datdba=app.oid) "
        "AND NOT EXISTS (SELECT 1 FROM pg_namespace n JOIN app ON n.nspowner=app.oid) "
        "AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN app ON c.relowner=app.oid) "
        "AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN app ON p.proowner=app.oid) "
        "AND NOT EXISTS (SELECT 1 FROM pg_default_acl a JOIN app ON EXISTS "
        "(SELECT 1 FROM aclexplode(a.defaclacl) x WHERE x.grantee=app.oid)) "
        "AND NOT has_database_privilege('sub2api_app', current_database(), 'TEMPORARY') "
        "AND EXISTS (SELECT 1 FROM pg_event_trigger WHERE "
        "evtname='sub2api_gate_guard_app_ddl' AND evtenabled IN ('O','A')) "
        "AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n "
        "ON n.oid=c.relnamespace WHERE n.nspname='public' "
        "AND c.relkind IN ('r','p') AND ("
        "has_table_privilege('sub2api_app', c.oid, 'TRIGGER') OR "
        "has_table_privilege('sub2api_app', c.oid, 'TRUNCATE') OR "
        "has_table_privilege('sub2api_app', c.oid, 'REFERENCES')))"
    )
    result = runner(
        [
            "docker",
            "exec",
            TARGET_POSTGRES,
            "sh",
            "-ec",
            'exec psql --no-psqlrc --quiet --tuples-only --no-align '
            '-v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" '
            '--command "$1"',
            "traffic-canary-role-gate",
            query,
        ],
        timeout=15,
    )
    if decoded_stdout(result) != "t":
        raise CanaryError("target database app role is not least privilege")


def require_runtime_app_data(*, runner=run_command):
    command = (
        "test -r /app/data/.installed && test -w /app/data && "
        "test ! -e /app/data/config.yaml && "
        "test -d /app/data/pages && test ! -L /app/data/pages && "
        "test \"$(stat -c '%u:%g:%a' /app/data/pages)\" = '1000:1000:755' && "
        "! find /app/data/pages -mindepth 1 -print -quit | grep -q . && "
        "! find /app/data -mindepth 1 -maxdepth 1 "
        "! -name .installed ! -name model_pricing.json "
        "! -name model_pricing.sha256 ! -name pages -print -quit | grep -q . && "
        "! find /app/data -type f \\( -name '*.log' -o -iname '*preview*' "
        "-o -iname '*capture*' -o -name config.yaml \\) -print -quit | grep -q ."
    )
    runner(["docker", "exec", TARGET_APP, "sh", "-ec", command], timeout=15)


def require_health(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", "/health", headers={"Connection": "close"})
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise CanaryError("Sub2API loopback health endpoint is not healthy")
    except (OSError, http.client.HTTPException) as error:
        raise CanaryError("Sub2API loopback health endpoint is unavailable") from error
    finally:
        connection.close()


def legacy_identity(names, *, runner=run_command):
    for name in names:
        require_running(name, runner=runner)
    require_port(names.app, 8080, runner=runner)
    require_health(8080)
    legacy_pg_mounts = mount_sources(names.postgres, runner=runner)
    if any(item.get("Source") == str(DATA_ROOT / "postgres") for item in legacy_pg_mounts):
        raise CanaryError("legacy PostgreSQL already uses the migrated target path")
    legacy_app_mounts = mount_sources(names.app, runner=runner)
    if any(item.get("Source") == str(DATA_ROOT / "app") for item in legacy_app_mounts):
        raise CanaryError("legacy Sub2API already uses the migrated target app path")
    dependency_hosts = runtime_dependency_hosts(names.app, runner=runner)
    require_legacy_dependency(
        names.app,
        names.postgres,
        dependency_hosts["database"],
        "PostgreSQL",
        runner=runner,
    )
    require_legacy_dependency(
        names.app,
        names.redis,
        dependency_hosts["redis"],
        "Redis",
        runner=runner,
    )
    return {
        "app": container_id(names.app, runner=runner),
        "postgres": pg_system_identifier(names.postgres, runner=runner),
        "redis": redis_run_identifier(names.redis, runner=runner),
    }


def validate_target_runtime(*, runner=run_command, require_empty_redis=False):
    require_no_active_swap()
    require_project_members(runner=runner)
    service_names = {
        TARGET_APP: "sub2api-traffic-canary",
        TARGET_POSTGRES: "traffic-canary-postgres",
        TARGET_REDIS: "traffic-canary-redis",
    }
    for container in TARGET_NAMES:
        require_running(container, require_healthy=True, runner=runner)
        require_labels(container, service_names[container], runner=runner)

    require_runtime_hardening(TARGET_APP, SUB2API_IMAGE, "1000:1000", runner=runner)
    require_runtime_hardening(TARGET_POSTGRES, POSTGRES_IMAGE, "70:70", runner=runner)
    require_runtime_hardening(TARGET_REDIS, REDIS_IMAGE, "999:1000", runner=runner)
    require_port(TARGET_APP, 8081, runner=runner)
    require_no_ports(TARGET_POSTGRES, runner=runner)
    require_no_ports(TARGET_REDIS, runner=runner)
    require_exact_bind(
        TARGET_APP,
        str(DATA_ROOT / "app"),
        "/app/data",
        False,
        runner=runner,
    )
    require_exact_bind(
        TARGET_POSTGRES,
        str(DATA_ROOT / "postgres"),
        "/var/lib/postgresql",
        False,
        runner=runner,
    )
    require_exact_bind(
        TARGET_REDIS,
        str(DATA_ROOT / "redis" / "users.acl"),
        "/etc/redis/users.acl",
        True,
        runner=runner,
    )
    require_binary_versions(runner=runner)
    require_redis_volatile(require_empty=require_empty_redis, runner=runner)
    run_postgres_gate(POSTGRES_RUNTIME_LOG_GATE, runner=runner)
    run_postgres_gate(REPO_DIR / "migrations" / "verify_conversation_guards.sql", runner=runner)
    run_postgres_gate(REPO_DIR / "migrations" / "verify_no_conversation_content.sql", runner=runner)
    require_app_role(runner=runner)
    require_runtime_app_data(runner=runner)
    require_health(8081)
    return {
        "app": container_id(TARGET_APP, runner=runner),
        "postgres": pg_system_identifier(TARGET_POSTGRES, runner=runner),
        "redis": redis_run_identifier(TARGET_REDIS, runner=runner),
    }


def require_distinct(legacy, target):
    for component in ("app", "postgres", "redis"):
        if not legacy.get(component) or legacy[component] == target.get(component):
            raise CanaryError(f"migrated target does not have a distinct {component} identity")


def compose_command(env_file, *arguments):
    return [
        "docker",
        "compose",
        "--project-name",
        PROJECT,
        "--env-file",
        str(env_file),
        "-f",
        str(COMPOSE_FILE),
        "--profile",
        PROFILE,
        *arguments,
    ]


def compose_environment(private_keys):
    environment = os.environ.copy()
    for key in tuple(environment):
        if key in private_keys or key.startswith("COMPOSE_"):
            environment.pop(key, None)
    environment["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    return environment


def stop_failed_stack(env_file, compose_env, *, runner=run_command):
    runner(
        compose_command(env_file, "down", "--remove-orphans", "--timeout", "10"),
        timeout=45,
        allow_failure=True,
        environment=compose_env,
    )


def start_canary(env_file, compose_env, names, *, runner=run_command):
    if any(container_exists(name, runner=runner) for name in TARGET_NAMES):
        raise CanaryError("traffic canary containers already exist; use status or verify")
    if project_members(runner=runner):
        raise CanaryError("traffic canary Compose project already contains containers")
    legacy = legacy_identity(names, runner=runner)
    started = False
    succeeded = False
    try:
        started = True
        runner(
            compose_command(
                env_file,
                "up",
                "--detach",
                "--no-build",
                "--pull",
                "never",
                "traffic-canary-postgres",
                "traffic-canary-redis",
            ),
            timeout=120,
            environment=compose_env,
        )
        wait_healthy(TARGET_POSTGRES, runner=runner)
        wait_healthy(TARGET_REDIS, runner=runner)

        target_data = {
            "postgres": pg_system_identifier(TARGET_POSTGRES, runner=runner),
            "redis": redis_run_identifier(TARGET_REDIS, runner=runner),
        }
        require_distinct(
            {"postgres": legacy["postgres"], "redis": legacy["redis"]},
            target_data,
        )
        require_redis_volatile(require_empty=True, runner=runner)
        run_postgres_gate(POSTGRES_RUNTIME_LOG_GATE, runner=runner)
        run_postgres_gate(
            REPO_DIR / "migrations" / "verify_conversation_guards.sql",
            runner=runner,
        )
        run_postgres_gate(
            REPO_DIR / "migrations" / "verify_no_conversation_content.sql",
            runner=runner,
        )
        require_app_role(runner=runner)

        runner(
            compose_command(
                env_file,
                "up",
                "--detach",
                "--no-build",
                "--pull",
                "never",
                "sub2api-traffic-canary",
            ),
            timeout=120,
            environment=compose_env,
        )
        for container in TARGET_NAMES:
            wait_healthy(container, runner=runner)
        target = validate_target_runtime(runner=runner)
        require_distinct(legacy, target)
        succeeded = True
    finally:
        if started and not succeeded:
            stop_failed_stack(env_file, compose_env, runner=runner)


class LegacyNames:
    def __init__(self, app, postgres, redis):
        self.app = app
        self.postgres = postgres
        self.redis = redis

    def __iter__(self):
        return iter((self.app, self.postgres, self.redis))


class LegacyContainerIds:
    def __init__(self, app, postgres, redis):
        self.app = app
        self.postgres = postgres
        self.redis = redis

    def __iter__(self):
        return iter((self.app, self.postgres, self.redis))


def require_exact_container_state(
    container,
    expected_id,
    *,
    running,
    runner=run_command,
):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_id or ""):
        raise UsageError("legacy container identity must be a full Docker ID")
    value = docker_inspect(
        container,
        "{{.Id}}|{{.State.Running}}",
        runner=runner,
    )
    actual_id, separator, state = value.partition("|")
    if (
        not separator
        or actual_id != expected_id
        or state not in {"true", "false"}
        or (state == "true") != running
    ):
        raise CanaryError("legacy container identity or runtime state changed")


def verify_stopped_legacy(names, identities, *, runner=run_command):
    require_exact_container_state(
        names.app,
        identities.app,
        running=False,
        runner=runner,
    )
    require_exact_container_state(
        names.postgres,
        identities.postgres,
        running=True,
        runner=runner,
    )
    require_exact_container_state(
        names.redis,
        identities.redis,
        running=True,
        runner=runner,
    )

    legacy_pg_mounts = mount_sources(names.postgres, runner=runner)
    if any(item.get("Source") == str(DATA_ROOT / "postgres") for item in legacy_pg_mounts):
        raise CanaryError("legacy PostgreSQL already uses the migrated target path")
    legacy_app_mounts = mount_sources(names.app, runner=runner)
    if any(item.get("Source") == str(DATA_ROOT / "app") for item in legacy_app_mounts):
        raise CanaryError("legacy Sub2API already uses the migrated target app path")

    legacy = {
        "app": identities.app,
        "postgres": pg_system_identifier(names.postgres, runner=runner),
        "redis": redis_run_identifier(names.redis, runner=runner),
    }
    target = validate_target_runtime(runner=runner)
    if set(identities) & {container_id(name, runner=runner) for name in TARGET_NAMES}:
        raise CanaryError("migrated target aliases a legacy Docker container")
    require_distinct(legacy, target)
    return legacy, target


def parse_arguments(argv):
    arguments = list(argv)
    mode = arguments.pop(0) if arguments else "check"
    if mode not in {"check", "status", "verify", "verify-stopped", "--apply"}:
        raise UsageError(
            "usage: traffic-canary.py [check|status|verify|verify-stopped|--apply] "
            "[--env-file PATH --wrangler-config PATH] [legacy container arguments]"
        )
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--env-file", type=pathlib.Path)
    parser.add_argument("--wrangler-config", type=pathlib.Path)
    parser.add_argument("--legacy-sub2api-container")
    parser.add_argument("--legacy-postgres-container")
    parser.add_argument("--legacy-redis-container")
    parser.add_argument("--legacy-sub2api-id")
    parser.add_argument("--legacy-postgres-id")
    parser.add_argument("--legacy-redis-id")
    try:
        options = parser.parse_args(arguments)
    except SystemExit as error:
        raise UsageError("invalid traffic canary arguments") from error
    if mode == "check":
        if arguments:
            raise UsageError("check mode does not accept runtime arguments")
        return mode, options, None
    if mode == "status":
        if arguments:
            raise UsageError("status mode does not accept runtime arguments")
        return mode, options, None
    required = (
        options.legacy_sub2api_container,
        options.legacy_postgres_container,
        options.legacy_redis_container,
    )
    if not all(required):
        raise UsageError(
            "verify, verify-stopped, and --apply require all three legacy container names"
        )
    names = LegacyNames(*required)
    validate_container_name(names.app, "legacy Sub2API container")
    validate_container_name(names.postgres, "legacy PostgreSQL container")
    validate_container_name(names.redis, "legacy Redis container")
    if len(set(names)) != 3:
        raise UsageError("legacy container names must be distinct")
    if mode == "--apply" and options.env_file is None:
        raise UsageError("--apply requires --env-file")
    if mode == "--apply" and options.wrangler_config is None:
        raise UsageError("--apply requires --wrangler-config")
    if mode == "verify" and (
        options.env_file is not None or options.wrangler_config is not None
    ):
        raise UsageError("verify does not read private configuration files")
    identity_values = (
        options.legacy_sub2api_id,
        options.legacy_postgres_id,
        options.legacy_redis_id,
    )
    if mode == "verify-stopped":
        if options.env_file is not None or options.wrangler_config is not None:
            raise UsageError("verify-stopped does not read private configuration files")
        if not all(identity_values):
            raise UsageError("verify-stopped requires all three full legacy container IDs")
        identities = LegacyContainerIds(*identity_values)
        for value in identities:
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise UsageError("legacy container identity must be a full Docker ID")
        return mode, options, (names, identities)
    if any(identity_values):
        raise UsageError("legacy container IDs are accepted only by verify-stopped")
    return mode, options, names


def main(argv=None, *, runner=run_command, stdin=None, stderr=None, stdout=None):
    argv = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin if stdin is None else stdin
    stderr = sys.stderr if stderr is None else stderr
    stdout = sys.stdout if stdout is None else stdout
    try:
        mode, options, names = parse_arguments(argv)
        check_compose_contract()
        if mode == "check":
            print(
                "traffic canary contract check passed; no environment file was read, "
                "no Docker command ran, and no service was changed",
                file=stdout,
            )
            return 0
        if os.geteuid() != 0:
            raise CanaryError("runtime traffic canary verification must run as root")
        if mode == "status":
            pin_local_docker_socket()
            validate_target_runtime(runner=runner)
            print(
                "migrated-target traffic canary is healthy on loopback 8081; "
                "legacy identity was not re-evaluated",
                file=stdout,
            )
            return 0
        if mode == "verify":
            pin_local_docker_socket()
            legacy = legacy_identity(names, runner=runner)
            target = validate_target_runtime(runner=runner)
            require_distinct(legacy, target)
            print(
                "migrated-target traffic canary and legacy stable identities are distinct",
                file=stdout,
            )
            return 0
        if mode == "verify-stopped":
            names, identities = names
            pin_local_docker_socket()
            verify_stopped_legacy(names, identities, runner=runner)
            print(
                "migrated-target traffic canary is distinct from the exact stopped "
                "legacy Sub2API and its running PostgreSQL/Redis dependencies",
                file=stdout,
            )
            return 0

        if not stdin.isatty() or not stderr.isatty():
            raise CanaryError("--apply requires a private interactive terminal")
        pin_local_docker_socket()
        runner([str(REPO_DIR / "deploy" / "require-clean-worktree.sh"), "check"], timeout=15)
        require_local_runtime_images(runner=runner)
        env_file, private_keys = parse_private_env(options.env_file)
        compose_env = compose_environment(private_keys)
        wrangler_config = require_private_config(
            options.wrangler_config, "private Wrangler config"
        )
        validate_storage()
        runner(
            [
                str(REPO_DIR / "deploy" / "security-preflight.sh"),
                "check",
                "--env-file",
                str(env_file),
                "--wrangler-config",
                str(wrangler_config),
            ],
            timeout=45,
        )
        runner(["docker", "compose", "version"], timeout=15)
        runner(
            compose_command(env_file, "config", "--quiet"),
            timeout=30,
            environment=compose_env,
        )
        start_canary(env_file, compose_env, names, runner=runner)
        print(
            "migrated-target traffic canary is ready on loopback 8081; run the "
            "metadata-only synthetic API canary before requesting an Nginx switch",
            file=stdout,
        )
        return 0
    except UsageError as error:
        print(str(error), file=stderr)
        return 2
    except CanaryError as error:
        print(str(error), file=stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
