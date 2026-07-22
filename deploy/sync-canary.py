#!/usr/bin/env python3
"""Guarded 3022 provisioning-sync canary and 3021 cutover controller."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import pathlib
import re
import socket
import stat
import subprocess
import sys
import time
import urllib.parse
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.sync-canary.yml"
SYNC_DOCKERFILE = ROOT / "sub2api-sync" / "Dockerfile"
SYNC_BUILD_CONTEXT = ROOT / "sub2api-sync"
ROLE_GATE = ROOT / "migrations" / "verify_sync_role_least_privilege.sql"
PRIVATE_ENV = ROOT / "deploy" / "private_env.py"
CLEAN_WORKTREE = ROOT / "deploy" / "require-clean-worktree.sh"
TRAFFIC_CONTROLLER = ROOT / "deploy" / "traffic-canary.py"
DATA_ROOT = pathlib.Path("/mnt/data/sub2api-gate")
STATE_DIRECTORY = pathlib.Path("/run/sub2api-gate")
SYNC_IMAGE_STATE = STATE_DIRECTORY / "sync-image.json"
DOCKER_SOCKET = pathlib.Path("/var/run/docker.sock")
TARGET_NETWORK = "sub2api-gate-traffic-canary_traffic-canary-data"
TARGET_POSTGRES = "sub2api-traffic-canary-postgres"
TARGET_APP = "sub2api-traffic-canary"
NONCE_REDIS = "sub2api-sync-canary-redis-nonce"
NONCE_REDIS_SERVICE = "sync-canary-redis-nonce"
CANARY_CONTAINER = "sub2api-sync-canary"
STABLE_CONTAINER = "sub2api-sync-stable"
LEGACY_UNIT = "sub2api-sync.service"
SYNC_CANARY_PORT = 3022
SYNC_STABLE_PORT = 3021
MAX_COMMAND_OUTPUT = 128 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_IMAGE_STATE_BYTES = 1024
STATE_UID = 0
STATE_GID = 0
SYNC_IMAGE = "sub2api-gate/sub2api-sync:pg18.4-r1"
SYNC_CANDIDATE_IMAGE = "sub2api-gate/sub2api-sync:pg18.4-r1-candidate"
POSTGRES_CLIENT_SOURCE = (
    "postgres@sha256:"
    "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
PYTHON_SOURCE = (
    "python@sha256:"
    "6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
)
SYNC_IMAGE_LABELS = {
    "io.sub2api-gate.sync-release": "pg18.4-r1",
    "io.sub2api-gate.postgresql-client": "18.4",
    "io.sub2api-gate.postgresql-client-source": POSTGRES_CLIENT_SOURCE,
    "io.sub2api-gate.python-source": PYTHON_SOURCE,
}
IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
GIT_HEAD_PATTERN = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


class CanaryError(RuntimeError):
    pass


def load_private_env_parser():
    try:
        spec = importlib.util.spec_from_file_location("sub2api_gate_private_env", PRIVATE_ENV)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except (AttributeError, ImportError, OSError) as error:
        raise CanaryError("private environment parser is unavailable") from error


def run_command(command, *, input_bytes=None, timeout=30, environment=None):
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CanaryError("required local command failed") from error
    if result.returncode != 0:
        raise CanaryError("required local command failed")
    if len(result.stdout) > MAX_COMMAND_OUTPUT:
        raise CanaryError("local command output exceeded the safety limit")
    return result


def decoded_stdout(result):
    return bytes(result.stdout).decode("utf-8", "strict").strip()


def current_git_head(*, runner=run_command):
    result = runner(
        ["git", "rev-parse", "--verify", "HEAD^{commit}"],
        timeout=10,
    )
    head = decoded_stdout(result)
    if not GIT_HEAD_PATTERN.fullmatch(head):
        raise CanaryError("release Git identity is invalid")
    return head


def validate_image_state_payload(payload):
    try:
        state = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CanaryError("sync image state is invalid") from error
    if not isinstance(state, dict) or set(state) != {
        "version",
        "image",
        "image_id",
        "git_head",
    }:
        raise CanaryError("sync image state is invalid")
    if (
        state["version"] != 1
        or state["image"] != SYNC_IMAGE
        or not isinstance(state["image_id"], str)
        or not IMAGE_ID_PATTERN.fullmatch(state["image_id"])
        or not isinstance(state["git_head"], str)
        or not GIT_HEAD_PATTERN.fullmatch(state["git_head"])
    ):
        raise CanaryError("sync image state is invalid")
    return state


def open_state_directory(*, create=False):
    created = False
    try:
        metadata = STATE_DIRECTORY.lstat()
    except FileNotFoundError:
        if not create:
            raise CanaryError("prebuilt sync image state is missing")
        try:
            STATE_DIRECTORY.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            pass
        except OSError as error:
            raise CanaryError("sync image state directory could not be created") from error
        try:
            metadata = STATE_DIRECTORY.lstat()
        except OSError as error:
            raise CanaryError("sync image state directory is unavailable") from error
    except OSError as error:
        raise CanaryError("sync image state directory is unavailable") from error

    if created:
        try:
            os.chmod(STATE_DIRECTORY, 0o700, follow_symlinks=False)
            os.chown(
                STATE_DIRECTORY,
                STATE_UID,
                STATE_GID,
                follow_symlinks=False,
            )
            metadata = STATE_DIRECTORY.lstat()
        except OSError as error:
            raise CanaryError("sync image state directory could not be secured") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or STATE_DIRECTORY.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != STATE_UID
        or metadata.st_gid != STATE_GID
    ):
        raise CanaryError("sync image state directory has unsafe permissions")

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(STATE_DIRECTORY, flags)
        opened = os.fstat(descriptor)
    except OSError as error:
        raise CanaryError("sync image state directory could not be opened") from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o700
        or opened.st_uid != STATE_UID
        or opened.st_gid != STATE_GID
    ):
        os.close(descriptor)
        raise CanaryError("sync image state directory changed during validation")
    return descriptor


def read_image_state():
    directory_descriptor = open_state_directory()
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        try:
            descriptor = os.open(SYNC_IMAGE_STATE.name, flags, dir_fd=directory_descriptor)
        except OSError as error:
            raise CanaryError("prebuilt sync image state is unavailable") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != STATE_UID
                or metadata.st_gid != STATE_GID
                or metadata.st_size > MAX_IMAGE_STATE_BYTES
            ):
                raise CanaryError("sync image state has unsafe permissions")
            chunks = []
            remaining = MAX_IMAGE_STATE_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if len(payload) > MAX_IMAGE_STATE_BYTES:
                raise CanaryError("sync image state is too large")
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_descriptor)
    return validate_image_state_payload(payload)


def write_image_state(image_id, git_head):
    state = validate_image_state_payload(
        json.dumps(
            {
                "version": 1,
                "image": SYNC_IMAGE,
                "image_id": image_id,
                "git_head": git_head,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    payload = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    directory_descriptor = open_state_directory(create=True)
    temporary_name = f".{SYNC_IMAGE_STATE.name}.{os.getpid()}.{os.urandom(8).hex()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    temporary_created = False
    try:
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
            temporary_created = True
        except OSError as error:
            raise CanaryError("sync image state could not be created") from error
        try:
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, STATE_UID, STATE_GID)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short state write")
                offset += written
            os.fsync(descriptor)
        except OSError as error:
            raise CanaryError("sync image state could not be written") from error
        finally:
            os.close(descriptor)
        try:
            os.replace(
                temporary_name,
                SYNC_IMAGE_STATE.name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            temporary_created = False
            os.fsync(directory_descriptor)
        except OSError as error:
            raise CanaryError("sync image state could not be committed") from error
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except OSError:
                pass
        os.close(directory_descriptor)


def inspect_local_sync_image(reference, *, expected_id=None, runner=run_command):
    result = runner(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}|{{.Os}}|{{.Architecture}}|{{json .Config.Labels}}",
            reference,
        ],
        timeout=15,
    )
    parts = decoded_stdout(result).split("|", 3)
    if len(parts) != 4:
        raise CanaryError("prebuilt sync image metadata is invalid")
    image_id, operating_system, architecture, labels_json = parts
    try:
        labels = json.loads(labels_json or "{}")
    except json.JSONDecodeError as error:
        raise CanaryError("prebuilt sync image labels are invalid") from error
    if (
        not IMAGE_ID_PATTERN.fullmatch(image_id)
        or operating_system != "linux"
        or architecture not in {"amd64", "arm64"}
        or not isinstance(labels, dict)
        or any(labels.get(name) != value for name, value in SYNC_IMAGE_LABELS.items())
        or (expected_id is not None and image_id != expected_id)
    ):
        raise CanaryError("prebuilt sync image identity does not match the release")
    version = decoded_stdout(
        runner(
            [
                "docker",
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--log-driver",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--user",
                "65532:65532",
                "--entrypoint",
                "/usr/local/bin/psql",
                image_id,
                "--version",
            ],
            timeout=30,
        )
    )
    if version != "psql (PostgreSQL) 18.4":
        raise CanaryError("prebuilt sync image does not contain the reviewed psql 18 client")
    return image_id


def prepare_sync_image(*, runner=run_command):
    git_head = current_git_head(runner=runner)
    runner(
        [
            "docker",
            "build",
            "--pull",
            "--no-cache",
            "--network",
            "none",
            "--tag",
            SYNC_CANDIDATE_IMAGE,
            str(SYNC_BUILD_CONTEXT),
        ],
        timeout=600,
    )
    image_id = inspect_local_sync_image(SYNC_CANDIDATE_IMAGE, runner=runner)
    runner(
        ["docker", "image", "tag", image_id, SYNC_IMAGE],
        timeout=15,
    )
    if inspect_local_sync_image(SYNC_IMAGE, expected_id=image_id, runner=runner) != image_id:
        raise CanaryError("prebuilt sync image tag could not be attested")
    write_image_state(image_id, git_head)
    return image_id


def require_prebuilt_sync_image(*, runner=run_command):
    state = read_image_state()
    if current_git_head(runner=runner) != state["git_head"]:
        raise CanaryError("prebuilt sync image belongs to a different Git revision")
    return inspect_local_sync_image(
        SYNC_IMAGE,
        expected_id=state["image_id"],
        runner=runner,
    )


def validate_contract():
    try:
        source = COMPOSE.read_text(encoding="utf-8")
        dockerfile = SYNC_DOCKERFILE.read_text(encoding="utf-8")
        role_gate = ROLE_GATE.read_text(encoding="utf-8")
    except OSError as error:
        raise CanaryError("sync canary release files are unavailable") from error

    required = (
        "name: sub2api-gate-sync-canary",
        'user: "65532:65532"',
        "read_only: true",
        'driver: "none"',
        '"127.0.0.1:3022:3021"',
        '"127.0.0.1:3021:3021"',
        "SUB2API_SYNC_DATABASE_HOST: traffic-canary-postgres",
        "SUB2API_SYNC_DATABASE_USER: sub2api_sync",
        "SUB2API_INTERNAL_LOGIN_URL: http://sub2api-traffic-canary:8080/api/v1/auth/login",
        "SUB2API_SYNC_REDIS_HOST: sync-canary-redis-nonce",
        "source: /mnt/data/sub2api-gate/redis/nonce",
        "create_host_path: false",
        "name: sub2api-gate-traffic-canary_traffic-canary-data",
        "sub2api-gate.request-path: never-v1",
        f"image: {SYNC_IMAGE}",
        "pull_policy: never",
    )
    for marker in required:
        if marker not in source:
            raise CanaryError("sync canary Compose contract is incomplete")
    forbidden = (
        "/var/run/docker.sock",
        "network_mode: host",
        "privileged: true",
        "build:",
    )
    if any(marker in source for marker in forbidden):
        raise CanaryError("sync canary Compose contract is unsafe")
    if "usage_logs" not in role_gate or "unexpected_table_privileges" not in role_gate:
        raise CanaryError("sync role verification gate is incomplete")
    dockerfile_required = (
        f"FROM {POSTGRES_CLIENT_SOURCE} AS postgres-client",
        f"FROM {PYTHON_SOURCE}",
        'test "$(psql --version)" = "psql (PostgreSQL) 18.4"',
        'io.sub2api-gate.sync-release="pg18.4-r1"',
    )
    if any(marker not in dockerfile for marker in dockerfile_required):
        raise CanaryError("sync image source contract is incomplete")
    if any(marker in dockerfile for marker in ("apk add", "apt-get", "dnf ", "yum ")):
        raise CanaryError("sync image source contract permits package-manager drift")


def parse_private_env(path):
    parser_module = load_private_env_parser()
    try:
        values = parser_module.read_private_environment(path)
        metadata = path.lstat()
    except (OSError, parser_module.PrivateEnvironmentError) as error:
        raise CanaryError(str(error)) from error
    if os.geteuid() == 0 and metadata.st_uid != 0:
        raise CanaryError("private environment file must be owned by root")
    required = {
        "SUB2API_DATA_ROOT",
        "POSTGRES_DB",
        "SUB2API_SYNC_DATABASE_PASSWORD",
        "SUB2API_SYNC_REDIS_PASSWORD",
        "SUB2API_SYNC_SECRET",
        "SUB2API_LOGIN_URL",
        "SUB2API_PUBLIC_BASE_URL",
    }
    if not required.issubset(values) or any(not values[name] for name in required):
        raise CanaryError("private environment file is missing sync settings")
    if values["SUB2API_DATA_ROOT"] != str(DATA_ROOT):
        raise CanaryError("private environment file has an unexpected data root")
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}", values["POSTGRES_DB"]):
        raise CanaryError("private environment file has an invalid database name")
    for name in (
        "SUB2API_SYNC_DATABASE_PASSWORD",
        "SUB2API_SYNC_REDIS_PASSWORD",
        "SUB2API_SYNC_SECRET",
    ):
        if len(values[name]) < 32:
            raise CanaryError("private environment file has a weak sync secret")
    for name in ("SUB2API_LOGIN_URL", "SUB2API_PUBLIC_BASE_URL"):
        try:
            parsed = urllib.parse.urlsplit(values[name])
        except ValueError as error:
            raise CanaryError("private environment file has an invalid public URL") from error
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise CanaryError("private environment file has an invalid public URL")
    return values


def compose_environment(private_values):
    # Compose receives runtime values only from the reviewed --env-file. Keep a
    # minimal process environment so shell variables cannot silently override
    # the private file or select a different project/context.
    environment = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
        if key in os.environ
    }
    environment["DOCKER_HOST"] = "unix:///var/run/docker.sock"
    return environment


def compose_command(env_file, profile, *arguments):
    return [
        "docker", "compose", "--file", str(COMPOSE), "--env-file", str(env_file),
        "--profile", profile, *arguments,
    ]


def require_apply_context(stdin):
    if os.geteuid() != 0:
        raise CanaryError("apply requires root")
    if not stdin.isatty():
        raise CanaryError("apply requires a private TTY")
    try:
        mode = DOCKER_SOCKET.stat().st_mode
    except OSError as error:
        raise CanaryError("local Docker socket is unavailable") from error
    if not stat.S_ISSOCK(mode):
        raise CanaryError("local Docker socket is invalid")


def require_storage_layout():
    required = {
        DATA_ROOT / "redis" / "nonce": (True, 0o700, 999, 1000),
        DATA_ROOT / "redis" / "nonce-users.acl": (False, 0o400, 999, 1000),
    }
    for path, (is_directory, mode, uid, gid) in required.items():
        try:
            metadata = path.lstat()
        except OSError as error:
            raise CanaryError("sync nonce storage is unavailable") from error
        valid_type = stat.S_ISDIR(metadata.st_mode) if is_directory else stat.S_ISREG(metadata.st_mode)
        if (
            not valid_type
            or path.is_symlink()
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_uid != uid
            or metadata.st_gid != gid
        ):
            raise CanaryError("sync nonce storage has unsafe permissions")


def require_target_runtime(*, runner=run_command):
    runner([sys.executable, str(TRAFFIC_CONTROLLER), "status"], timeout=30)
    result = runner(
        ["docker", "network", "inspect", TARGET_NETWORK, "--format", "{{json .Containers}}"],
        timeout=10,
    )
    try:
        containers = json.loads(decoded_stdout(result))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise CanaryError("migrated target network could not be verified") from error
    names = {str(item.get("Name") or "") for item in containers.values() if isinstance(item, dict)}
    if not {TARGET_POSTGRES, TARGET_APP}.issubset(names):
        raise CanaryError("migrated target network is missing required services")


def require_sync_role(*, runner=run_command):
    try:
        sql = ROLE_GATE.read_bytes()
    except OSError as error:
        raise CanaryError("sync role verification gate is unavailable") from error
    result = runner(
        [
            "docker", "exec", "-i", TARGET_POSTGRES, "sh", "-ec",
            'PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=15000" '
            'exec psql --no-psqlrc --quiet --tuples-only --no-align '
            '-v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
        ],
        input_bytes=sql,
        timeout=20,
    )
    if decoded_stdout(result) != "ok":
        raise CanaryError("target sync database role is not least privilege")


def inspect_sync_container(name, expected_port, expected_image_id, *, runner=run_command):
    template = (
        "{{.Image}}|{{.Config.Image}}|"
        "{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|"
        "{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.LogConfig.Type}}|"
        "{{json .HostConfig.Binds}}|{{json .NetworkSettings.Networks}}|{{json .Config.Labels}}"
    )
    result = runner(["docker", "inspect", "--format", template, name], timeout=10)
    parts = decoded_stdout(result).split("|", 9)
    if len(parts) != 10:
        raise CanaryError("sync container identity is invalid")
    (
        image_id,
        configured_image,
        running,
        health,
        user,
        read_only,
        log_driver,
        binds_json,
        networks_json,
        labels_json,
    ) = parts
    try:
        binds = json.loads(binds_json or "[]")
        networks = json.loads(networks_json or "{}")
        labels = json.loads(labels_json or "{}")
    except json.JSONDecodeError as error:
        raise CanaryError("sync container metadata could not be verified") from error
    expected_service = (
        "sub2api-sync-canary" if name == CANARY_CONTAINER else "sub2api-sync-stable"
    )
    if (
        image_id != expected_image_id
        or configured_image != SYNC_IMAGE
        or running != "true"
        or health != "healthy"
        or user != "65532:65532"
        or read_only != "true"
        or log_driver != "none"
        or any("docker.sock" in str(binding) for binding in (binds or []))
        or TARGET_NETWORK not in networks
        or labels.get("com.docker.compose.project") != "sub2api-gate-sync-canary"
        or labels.get("com.docker.compose.service") != expected_service
        or labels.get("sub2api-gate.request-path") != "never-v1"
    ):
        raise CanaryError("sync container runtime contract failed")
    port = decoded_stdout(runner(["docker", "port", name, "3021/tcp"], timeout=10))
    if port != f"127.0.0.1:{expected_port}":
        raise CanaryError("sync container is not loopback-only")


def inspect_nonce_redis(*, runner=run_command):
    template = (
        "{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}|"
        "{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.LogConfig.Type}}|"
        "{{.HostConfig.Memory}}|{{json .Config.Cmd}}|{{json .Mounts}}|"
        "{{json .NetworkSettings.Networks}}|{{json .Config.Labels}}"
    )
    result = runner(["docker", "inspect", "--format", template, NONCE_REDIS], timeout=10)
    parts = decoded_stdout(result).split("|", 9)
    if len(parts) != 10:
        raise CanaryError("sync nonce Redis identity is invalid")
    (
        running,
        health,
        user,
        read_only,
        log_driver,
        memory,
        command_json,
        mounts_json,
        networks_json,
        labels_json,
    ) = parts
    try:
        command = json.loads(command_json or "[]")
        mounts = json.loads(mounts_json or "[]")
        networks = json.loads(networks_json or "{}")
        labels = json.loads(labels_json or "{}")
    except json.JSONDecodeError as error:
        raise CanaryError("sync nonce Redis metadata could not be verified") from error
    sources = {str(mount.get("Source") or "") for mount in mounts if isinstance(mount, dict)}
    expected_command_values = {
        "--appendonly": "yes",
        "--appendfsync": "always",
        "--save": "",
        "--maxmemory": "32mb",
        "--maxmemory-policy": "noeviction",
    }
    try:
        command_matches = all(
            command[command.index(option) + 1] == value
            for option, value in expected_command_values.items()
        )
    except (AttributeError, ValueError, IndexError):
        command_matches = False
    if (
        running != "true"
        or health != "healthy"
        or user != "999:1000"
        or read_only != "true"
        or log_driver != "none"
        or memory != str(128 * 1024 * 1024)
        or not command_matches
        or str(DATA_ROOT / "redis" / "nonce") not in sources
        or str(DATA_ROOT / "redis" / "nonce-users.acl") not in sources
        or TARGET_NETWORK not in networks
        or labels.get("com.docker.compose.project") != "sub2api-gate-sync-canary"
        or labels.get("com.docker.compose.service") != NONCE_REDIS_SERVICE
    ):
        raise CanaryError("sync nonce Redis runtime contract failed")


def wait_for_container(
    name,
    expected_port,
    expected_image_id,
    *,
    runner=run_command,
    clock=time.monotonic,
    sleeper=time.sleep,
):
    deadline = clock() + 75
    while True:
        try:
            inspect_sync_container(
                name,
                expected_port,
                expected_image_id,
                runner=runner,
            )
            return
        except CanaryError:
            if clock() >= deadline:
                raise CanaryError("sync container did not become healthy")
            sleeper(1)


def read_bounded_response(response):
    header = response.getheader("content-length")
    if header is None or not header.isdigit() or int(header) > MAX_RESPONSE_BYTES:
        raise CanaryError("sync response size is invalid")
    body = response.read(int(header) + 1)
    if len(body) != int(header):
        raise CanaryError("sync response body is invalid")
    return body


def signed_status_request(port, secret, *, timestamp=None, nonce=None, probe_uuid=None):
    if len(secret) < 32:
        raise CanaryError("sync HMAC secret is invalid")
    timestamp = str(int(time.time()) if timestamp is None else timestamp)
    nonce = nonce or os.urandom(16).hex()
    probe_uuid = probe_uuid or str(uuid.uuid4())
    body = json.dumps(
        {"action": "status", "uuid": probe_uuid, "username": "sync-canary-probe"},
        separators=(",", ":"),
    ).encode()
    signature = hmac.new(
        secret.encode(), timestamp.encode() + b"." + nonce.encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    headers = {
        "content-type": "application/json",
        "content-length": str(len(body)),
        "x-sub2api-sync-timestamp": timestamp,
        "x-sub2api-sync-nonce": nonce,
        "x-sub2api-sync-signature": signature,
        "x-request-id": os.urandom(16).hex(),
        "connection": "close",
    }
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=6)
    try:
        connection.request("POST", "/provision", body=body, headers=headers)
        response = connection.getresponse()
        status = response.status
        response_body = read_bounded_response(response)
    except (OSError, http.client.HTTPException) as error:
        raise CanaryError("sync signed status probe is unavailable") from error
    finally:
        connection.close()
    return status, response_body, headers, body


def replay_request(port, headers, body):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=6)
    try:
        connection.request("POST", "/provision", body=body, headers=headers)
        response = connection.getresponse()
        status = response.status
        read_bounded_response(response)
        return status
    except (OSError, http.client.HTTPException) as error:
        raise CanaryError("sync replay probe is unavailable") from error
    finally:
        connection.close()


def verify_signed_status(port, secret):
    status, body, headers, request_body = signed_status_request(port, secret)
    if status != 200:
        raise CanaryError("sync signed status probe failed")
    try:
        payload = json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CanaryError("sync signed status response is invalid") from error
    if payload.get("ok") is not True or payload.get("action") != "status":
        raise CanaryError("sync signed status response is invalid")
    if replay_request(port, headers, request_body) != 401:
        raise CanaryError("sync nonce replay protection failed")


def prompt_secret(secret_reader=getpass.getpass):
    try:
        secret = secret_reader("Sub2API sync HMAC secret: ")
    except (EOFError, KeyboardInterrupt) as error:
        raise CanaryError("sync HMAC secret was not provided") from error
    if len(secret) < 32:
        raise CanaryError("sync HMAC secret is invalid")
    return secret


def require_port_free(port):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        probe.bind(("127.0.0.1", port))
    except OSError as error:
        raise CanaryError("stable sync loopback port is still occupied") from error
    finally:
        probe.close()


def start_profile(env_file, profile, service, environment, *, runner=run_command):
    runner(
        compose_command(
            env_file,
            profile,
            "up",
            "--detach",
            "--no-build",
            "--pull",
            "never",
            NONCE_REDIS_SERVICE,
            service,
        ),
        timeout=180,
        environment=environment,
    )


def stop_service(env_file, profile, service, environment, *, runner=run_command):
    runner(
        compose_command(env_file, profile, "stop", "--timeout", "15", service),
        timeout=30,
        environment=environment,
    )


def systemctl(action, *, runner=run_command):
    return runner(["systemctl", action, LEGACY_UNIT], timeout=30)


def start_canary(env_file, environment, secret, expected_image_id, *, runner=run_command):
    require_target_runtime(runner=runner)
    require_sync_role(runner=runner)
    try:
        start_profile(env_file, "sync-canary", CANARY_CONTAINER, environment, runner=runner)
        wait_for_container(
            CANARY_CONTAINER,
            SYNC_CANARY_PORT,
            expected_image_id,
            runner=runner,
        )
        inspect_nonce_redis(runner=runner)
        verify_signed_status(SYNC_CANARY_PORT, secret)
    except Exception:
        for service in (CANARY_CONTAINER, NONCE_REDIS_SERVICE):
            try:
                stop_service(env_file, "sync-canary", service, environment, runner=runner)
            except CanaryError:
                pass
        raise CanaryError("sync canary start failed and temporary services were stopped")


def require_legacy_service(*, runner=run_command):
    runner(["systemctl", "is-active", "--quiet", LEGACY_UNIT], timeout=10)
    result = runner(
        ["systemctl", "show", "--property=User", "--value", LEGACY_UNIT], timeout=10
    )
    if decoded_stdout(result) not in {"", "root"}:
        raise CanaryError("legacy sync service is not the reviewed root service")


def promote(env_file, environment, secret, expected_image_id, *, runner=run_command):
    inspect_sync_container(
        CANARY_CONTAINER,
        SYNC_CANARY_PORT,
        expected_image_id,
        runner=runner,
    )
    inspect_nonce_redis(runner=runner)
    verify_signed_status(SYNC_CANARY_PORT, secret)
    require_legacy_service(runner=runner)
    systemctl("stop", runner=runner)
    legacy_stopped = True
    try:
        require_port_free(SYNC_STABLE_PORT)
        start_profile(env_file, "sync-stable", STABLE_CONTAINER, environment, runner=runner)
        wait_for_container(
            STABLE_CONTAINER,
            SYNC_STABLE_PORT,
            expected_image_id,
            runner=runner,
        )
        verify_signed_status(SYNC_STABLE_PORT, secret)
    except Exception:
        try:
            stop_service(env_file, "sync-stable", STABLE_CONTAINER, environment, runner=runner)
        except CanaryError:
            pass
        if legacy_stopped:
            try:
                systemctl("start", runner=runner)
            except CanaryError:
                pass
        raise CanaryError("stable sync cutover failed and legacy recovery was attempted")
    try:
        systemctl("disable", runner=runner)
    except CanaryError:
        try:
            stop_service(env_file, "sync-stable", STABLE_CONTAINER, environment, runner=runner)
            systemctl("start", runner=runner)
        except CanaryError:
            pass
        raise CanaryError("legacy sync disable failed and legacy recovery was attempted")
    stop_service(env_file, "sync-canary", CANARY_CONTAINER, environment, runner=runner)


def rollback(env_file, environment, secret, expected_image_id, *, runner=run_command):
    inspect_sync_container(
        STABLE_CONTAINER,
        SYNC_STABLE_PORT,
        expected_image_id,
        runner=runner,
    )
    inspect_nonce_redis(runner=runner)
    verify_signed_status(SYNC_STABLE_PORT, secret)
    stop_service(env_file, "sync-stable", STABLE_CONTAINER, environment, runner=runner)
    try:
        systemctl("enable", runner=runner)
        systemctl("start", runner=runner)
        verify_signed_status(SYNC_STABLE_PORT, secret)
    except Exception:
        try:
            systemctl("stop", runner=runner)
        except CanaryError:
            pass
        start_profile(env_file, "sync-stable", STABLE_CONTAINER, environment, runner=runner)
        wait_for_container(
            STABLE_CONTAINER,
            SYNC_STABLE_PORT,
            expected_image_id,
            runner=runner,
        )
        raise CanaryError("legacy sync recovery failed; stable container was restored")


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "action",
        choices=(
            "check",
            "prepare-image",
            "start",
            "verify",
            "promote",
            "rollback",
            "status",
        ),
        nargs="?",
        default="check",
    )
    result.add_argument("--apply", action="store_true")
    result.add_argument("--env-file", type=pathlib.Path)
    return result


def main(argv=None, *, runner=run_command, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr, secret_reader=getpass.getpass):
    options = parser().parse_args(argv)
    try:
        validate_contract()
        if options.action == "check":
            if options.apply:
                raise CanaryError("check mode does not accept --apply")
            print("sync canary contract check passed; no private file was read and no service was changed", file=stdout)
            return 0

        if options.action in {"prepare-image", "start", "promote", "rollback"} and not options.apply:
            print(f"sync canary {options.action} dry-run passed; add --apply from a private root TTY to change services", file=stdout)
            return 0

        require_apply_context(stdin)
        runner([str(CLEAN_WORKTREE)], timeout=15)
        if options.action == "prepare-image":
            prepare_sync_image(runner=runner)
            print(
                "sync canary prepare-image completed; exact image identity was recorded",
                file=stdout,
            )
            return 0
        if options.env_file is None or not options.env_file.is_absolute():
            raise CanaryError("an absolute private --env-file is required")
        private_values = parse_private_env(options.env_file)
        environment = compose_environment(private_values)
        require_storage_layout()
        runner(compose_command(options.env_file, "sync-canary", "config", "--quiet"), timeout=30, environment=environment)
        expected_image_id = require_prebuilt_sync_image(runner=runner)

        if options.action == "status":
            require_target_runtime(runner=runner)
            print("sync target runtime is available; no service was changed", file=stdout)
            return 0

        secret = prompt_secret(secret_reader)
        if not hmac.compare_digest(secret, private_values["SUB2API_SYNC_SECRET"]):
            raise CanaryError("provided sync HMAC secret does not match the private environment")
        if options.action == "start":
            start_canary(
                options.env_file,
                environment,
                secret,
                expected_image_id,
                runner=runner,
            )
        elif options.action == "verify":
            require_sync_role(runner=runner)
            inspect_sync_container(
                CANARY_CONTAINER,
                SYNC_CANARY_PORT,
                expected_image_id,
                runner=runner,
            )
            inspect_nonce_redis(runner=runner)
            verify_signed_status(SYNC_CANARY_PORT, secret)
        elif options.action == "promote":
            promote(
                options.env_file,
                environment,
                secret,
                expected_image_id,
                runner=runner,
            )
        elif options.action == "rollback":
            rollback(
                options.env_file,
                environment,
                secret,
                expected_image_id,
                runner=runner,
            )
        print(f"sync canary {options.action} completed", file=stdout)
        return 0
    except CanaryError as error:
        print(str(error), file=stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
