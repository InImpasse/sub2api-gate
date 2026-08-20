#!/usr/bin/python3 -I
"""Privately recover the Cloudflare Worker administrator password and canonical TOTP seed."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import pathlib
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse


ROOT = pathlib.Path(__file__).resolve().parents[1]
PUBLISHER_PATH = ROOT / "deploy/local-worker-publish.py"
PUBLISHER_SPEC = importlib.util.spec_from_file_location("local_worker_publish_for_recovery", PUBLISHER_PATH)
PUBLISHER = importlib.util.module_from_spec(PUBLISHER_SPEC)
PUBLISHER_SPEC.loader.exec_module(PUBLISHER)
WORKER = ROOT / "worker-allow-ip"
CONFIG = WORKER / "wrangler.private.jsonc"
VERIFIER = ROOT / "deploy/verify-worker-secret-list.mjs"
NODE = pathlib.Path(os.environ.get("SUB2API_LOCAL_NODE", shutil.which("node") or ""))
SEED_RE = re.compile(r"[A-Z2-7]{16,128}\Z")
VERSION_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
RECOVERY_RELEASE = PUBLISHER.COMPATIBILITY_RELEASE
TOOLCHAIN_DIGEST = hashlib.sha256(
    "\0".join(
        f"{name}={digest}"
        for name, digest in sorted(PUBLISHER.REVIEWED_TOOLCHAIN_SHA256.items())
    ).encode("ascii")
).hexdigest()
RECOVERY_TAG = f"admin-recovery-{RECOVERY_RELEASE[:8]}-{TOOLCHAIN_DIGEST[:8]}"
RECOVERY_MESSAGE = f"src={RECOVERY_RELEASE} toolchain={TOOLCHAIN_DIGEST}"
MAX_WRANGLER_JSON_BYTES = 64 * 1024
ADMIN_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_ADMIN_PASSWORD_CHARACTERS = 4096
MAX_ADMIN_TOTP_SEED_CHARACTERS = 128
MAX_PRIVATE_SECRET_FILE_BYTES = MAX_ADMIN_PASSWORD_CHARACTERS + 2
MAX_ADMIN_LOGIN_FORM_BYTES = 32 * 1024
LEGACY_COMPATIBILITY_SECRET_NAMES = frozenset({"ADMIN_PASSWORD_HASH"})
REMOTE_OUTCOME_UNKNOWN = (
    "remote_outcome_unknown: exact Worker state could not be proven; "
    "do not retry until the remote version and deployment are reconciled"
)
READBACK_ATTEMPTS = 3
READBACK_RETRY_SECONDS = 0.25
LOCAL_RECOVERY_DIRECTORY_NAME = ".admin-recovery"


class AdminRecoveryError(RuntimeError):
    pass


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def environment(home, node):
    return {
        "PATH": f"{node.parent}:/usr/bin:/bin",
        "HOME": str(home),
        "WRANGLER_SEND_METRICS": "false",
        "CLOUDFLARE_INCLUDE_PROCESS_ENV": "false",
        "CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV": "false",
    }


def run(arguments, *, env, cwd=ROOT, input_text=None, runner=subprocess.run):
    result = runner(
        [str(item) for item in arguments],
        cwd=str(cwd),
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AdminRecoveryError("administrator recovery gate failed")
    return result


def run_remote_mutation(arguments, *, env, cwd=ROOT, runner=subprocess.run):
    try:
        return runner(
            [str(item) for item in arguments],
            cwd=str(cwd),
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _strict_object(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON field")
        document[key] = value
    return document


def _parse_json(payload, label):
    if not isinstance(payload, str) or len(payload.encode("utf-8")) > MAX_WRANGLER_JSON_BYTES:
        raise AdminRecoveryError(f"{label} is invalid")
    try:
        return json.loads(payload, object_pairs_hook=_strict_object)
    except (json.JSONDecodeError, UnicodeError, ValueError) as error:
        raise AdminRecoveryError(f"{label} is invalid") from error


def _required_secret_names(path):
    try:
        payload = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as error:
        raise AdminRecoveryError("required Worker Secret manifest is unavailable") from error
    document = _parse_json(payload, "required Worker Secret manifest")
    required = document.get("required") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or document.get("version") != 1
        or not isinstance(required, list)
        or not required
        or any(not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", name) for name in required)
        or len(set(required)) != len(required)
    ):
        raise AdminRecoveryError("required Worker Secret manifest is invalid")
    return frozenset(required)


def _create_private_file(path, payload=b""):
    target = pathlib.Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(target, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            written = 0
            while written < len(payload):
                written += os.write(descriptor, payload[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        if descriptor is not None:
            try:
                target.unlink()
            except OSError:
                pass
        raise AdminRecoveryError("private administrator recovery file could not be created") from error
    return target


def _remove_recovery_files(paths):
    first_error = None
    for path in paths:
        try:
            pathlib.Path(path).unlink()
        except FileNotFoundError:
            pass
        except OSError as error:
            if first_error is None:
                first_error = error
    return first_error


def _read_private_secret_line(path, *, expected_uid, max_characters, label):
    target = pathlib.Path(path)
    if not target.is_absolute():
        raise AdminRecoveryError(f"{label} path must be absolute")
    try:
        metadata = target.lstat()
        parent = target.parent.lstat()
        resolved = target.resolve(strict=True)
        worktree = ROOT.resolve()
    except OSError as error:
        raise AdminRecoveryError(f"{label} is unavailable") from error
    try:
        relative = resolved.relative_to(worktree)
    except ValueError:
        relative = None
    if relative is not None and (
        len(relative.parts) < 2
        or relative.parts[0] != LOCAL_RECOVERY_DIRECTORY_NAME
    ):
        raise AdminRecoveryError(
            f"{label} in the Git worktree must be under {LOCAL_RECOVERY_DIRECTORY_NAME}/"
        )
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 1
        or metadata.st_size > MAX_PRIVATE_SECRET_FILE_BYTES
        or not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != expected_uid
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise AdminRecoveryError(f"{label} is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise AdminRecoveryError(f"{label} is unavailable") from error
    try:
        opened = os.fstat(descriptor)
        payload = os.read(descriptor, MAX_PRIVATE_SECRET_FILE_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_uid != expected_uid
        or len(payload) > MAX_PRIVATE_SECRET_FILE_BYTES
        or (metadata.st_dev, metadata.st_ino, metadata.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
    ):
        raise AdminRecoveryError(f"{label} is invalid")
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeError as error:
        raise AdminRecoveryError(f"{label} is invalid") from error
    if "\0" in text:
        raise AdminRecoveryError(f"{label} is invalid")
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n") or text.endswith("\r"):
        text = text[:-1]
    if "\n" in text or "\r" in text or not text or len(text) > max_characters:
        raise AdminRecoveryError(f"{label} is invalid")
    return text


def _read_wrangler_output(path, expected_type):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise AdminRecoveryError("Wrangler structured output is unavailable") from error
    if (
        target.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > MAX_WRANGLER_JSON_BYTES
    ):
        raise AdminRecoveryError("Wrangler structured output is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise AdminRecoveryError("Wrangler structured output is unavailable") from error
    try:
        opened = os.fstat(descriptor)
        payload = os.read(descriptor, MAX_WRANGLER_JSON_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o600
        or len(payload) > MAX_WRANGLER_JSON_BYTES
        or (metadata.st_dev, metadata.st_ino, metadata.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
    ):
        raise AdminRecoveryError("Wrangler structured output is invalid")
    try:
        lines = payload.decode("utf-8", "strict").splitlines()
    except UnicodeError as error:
        raise AdminRecoveryError("Wrangler structured output is invalid") from error
    if len(lines) != 1:
        raise AdminRecoveryError("Wrangler structured output is invalid")
    document = _parse_json(lines[0], "Wrangler structured output")
    if not isinstance(document, dict) or document.get("type") != expected_type or document.get("version") != 1:
        raise AdminRecoveryError("Wrangler structured output is invalid")
    return document


def _read_remote_mutation_record(path, expected_type):
    try:
        return _read_wrangler_output(path, expected_type)
    except AdminRecoveryError as error:
        raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN) from error


def _remote_version_ids(node, wrangler, config, *, env, cwd, runner):
    result = run_remote_mutation(
        [node, wrangler, "versions", "list", "--json", "--config", config],
        env=env,
        cwd=cwd,
        runner=runner,
    )
    if result is None or result.returncode != 0:
        raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN)
    document = _parse_json(result.stdout, "Worker version list")
    if not isinstance(document, list):
        raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN)
    return document


def _recover_uploaded_version_id(before, after):
    prior = {
        item.get("id")
        for item in before
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    created = [
        item
        for item in after
        if isinstance(item, dict)
        and item.get("id") not in prior
        and isinstance(item.get("id"), str)
    ]
    candidates = [
        item.get("id")
        for item in created
        if isinstance(item.get("annotations"), dict)
        and item["annotations"].get("workers/tag") == RECOVERY_TAG
        and item["annotations"].get("workers/message") == RECOVERY_MESSAGE
    ]
    if len(created) != 1 or len(candidates) != 1:
        raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN)
    return _validated_remote_identifier(candidates[0], "uploaded Worker version ID")


def _validate_latest_reviewed_version(versions, version_id):
    if not versions or not isinstance(versions[0], dict):
        raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN)
    latest = versions[0]
    annotations = latest.get("annotations")
    if (
        latest.get("id") != version_id
        or not isinstance(annotations, dict)
        or annotations.get("workers/tag") != RECOVERY_TAG
        or annotations.get("workers/message") != RECOVERY_MESSAGE
    ):
        raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN)


def _recover_deployment_id(payload, version_id):
    document = _parse_json(payload, "Worker deployment readback")
    versions = document.get("versions") if isinstance(document, dict) else None
    annotations = document.get("annotations") if isinstance(document, dict) else None
    deployment_id = document.get("id") if isinstance(document, dict) else None
    if (
        not isinstance(annotations, dict)
        or annotations.get("workers/message") != RECOVERY_MESSAGE
        or versions != [{"version_id": version_id, "percentage": 100}]
    ):
        raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN)
    return _validated_remote_identifier(deployment_id, "Worker deployment ID")


def _validated_identifier(value, label):
    normalized = str(value or "").lower()
    if not VERSION_ID_RE.fullmatch(normalized):
        raise AdminRecoveryError(f"{label} is invalid")
    return normalized


def _validated_remote_identifier(value, label):
    try:
        return _validated_identifier(value, label)
    except AdminRecoveryError as error:
        raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN) from error


def _validate_version_view(payload, version_id, required_secrets):
    document = _parse_json(payload, "Worker version readback")
    annotations = document.get("annotations") if isinstance(document, dict) else None
    resources = document.get("resources") if isinstance(document, dict) else None
    bindings = resources.get("bindings") if isinstance(resources, dict) else None
    secret_names = {
        binding.get("name")
        for binding in bindings or []
        if isinstance(binding, dict) and binding.get("type") == "secret_text"
    }
    if (
        document.get("id") != version_id
        or not isinstance(annotations, dict)
        or annotations.get("workers/tag") != RECOVERY_TAG
        or annotations.get("workers/message") != RECOVERY_MESSAGE
        or not isinstance(bindings, list)
        or not secret_names.issuperset(required_secrets)
        or secret_names - set(required_secrets) - LEGACY_COMPATIBILITY_SECRET_NAMES
    ):
        raise AdminRecoveryError("uploaded Worker version attestation does not match")


def _validate_deployment_status(payload, deployment_id, version_id):
    document = _parse_json(payload, "Worker deployment readback")
    annotations = document.get("annotations") if isinstance(document, dict) else None
    versions = document.get("versions") if isinstance(document, dict) else None
    expected_versions = [{"version_id": version_id, "percentage": 100}]
    if (
        document.get("id") != deployment_id
        or not isinstance(annotations, dict)
        or annotations.get("workers/message") != RECOVERY_MESSAGE
        or versions != expected_versions
    ):
        raise AdminRecoveryError("deployed Worker version attestation does not match")


def reconcile_remote_readback(
    arguments,
    validator,
    *,
    env,
    cwd,
    runner=subprocess.run,
    sleeper=time.sleep,
):
    for attempt in range(READBACK_ATTEMPTS):
        if attempt:
            sleeper(READBACK_RETRY_SECONDS)
        result = run_remote_mutation(arguments, env=env, cwd=cwd, runner=runner)
        if result is None or result.returncode != 0:
            continue
        try:
            validator(result.stdout)
        except AdminRecoveryError:
            continue
        return
    raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN)


def check_secret_names_at(node, wrangler, config, manifest, *, env, cwd, runner=subprocess.run):
    listed = run(
        [node, wrangler, "secret", "list", "--format", "json", "--config", config],
        env=env,
        cwd=cwd,
        runner=runner,
    )
    run(
        [node, VERIFIER, manifest, "--forbid-totp-rotation-staging"],
        env=env,
        cwd=cwd,
        input_text=listed.stdout,
        runner=runner,
    )


def _remote_secret_names(node, wrangler, config, *, env, cwd, runner):
    result = run_remote_mutation(
        [node, wrangler, "secret", "list", "--format", "json", "--config", config],
        env=env,
        cwd=cwd,
        runner=runner,
    )
    if result is None or result.returncode != 0:
        raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN)
    payload = _parse_json(result.stdout, "Worker Secret list")
    if not isinstance(payload, list):
        raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN)
    names = set()
    for item in payload:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN)
        names.add(item["name"])
    return names


def _validate_credential_secret_names(names, required):
    allowed = set(required) | LEGACY_COMPATIBILITY_SECRET_NAMES
    if not set(required).issubset(names) or names - allowed:
        raise AdminRecoveryError("remote Worker Secret name set is invalid")


def migrate_admin_credentials(
    node,
    wrangler,
    config,
    manifest,
    password,
    seed,
    base_version_id,
    *,
    env,
    cwd,
    runner=subprocess.run,
):
    required = _required_secret_names(manifest)
    before = _remote_secret_names(node, wrangler, config, env=env, cwd=cwd, runner=runner)
    _validate_credential_secret_names(before, required)
    versions_before = _remote_version_ids(node, wrangler, config, env=env, cwd=cwd, runner=runner)
    _validate_latest_reviewed_version(versions_before, base_version_id)
    payload = json.dumps(
        {
            "ADMIN_PASSWORD_PBKDF2": password_record(password),
            "ADMIN_TOTP_SECRET": validate_seed(seed),
        },
        separators=(",", ":"),
    )
    try:
        run_remote_mutation(
            [
                node,
                wrangler,
                "versions",
                "secret",
                "bulk",
                "--config",
                config,
                "--tag",
                RECOVERY_TAG,
                "--message",
                RECOVERY_MESSAGE,
            ],
            env=env,
            cwd=cwd,
            runner=lambda arguments, **kwargs: runner(arguments, input=payload, **kwargs),
        )
    finally:
        payload = ""
    versions_after = _remote_version_ids(node, wrangler, config, env=env, cwd=cwd, runner=runner)
    version_id = _recover_uploaded_version_id(versions_before, versions_after)
    _validate_latest_reviewed_version(versions_after, version_id)
    after = _remote_secret_names(node, wrangler, config, env=env, cwd=cwd, runner=runner)
    _validate_credential_secret_names(after, required)
    return version_id


def publish_recovery_version(
    stage_dir,
    password,
    seed,
    node,
    *,
    env,
    runner=subprocess.run,
    login_prover=None,
    sleeper=time.sleep,
):
    stage = pathlib.Path(stage_dir)
    worker = stage / "worker-allow-ip"
    config = worker / "wrangler.private.jsonc"
    manifest = worker / "required-secrets.json"
    wrangler = worker / "node_modules/wrangler/bin/wrangler.js"
    required_secrets = _required_secret_names(manifest)
    normalized_seed = validate_seed(seed)
    validate_password(password)
    username, _hostname = _recovery_login_settings(config)
    _build_admin_login_form(username, password, normalized_seed, 0)
    upload_output = stage / f".wrangler-upload-{secrets.token_hex(8)}.json"
    deploy_output = stage / f".wrangler-deploy-{secrets.token_hex(8)}.json"
    operation_error = None
    try:
        _create_private_file(upload_output)
        _create_private_file(deploy_output)
        check_secret_names_at(node, wrangler, config, manifest, env=env, cwd=stage, runner=runner)
        versions_before = _remote_version_ids(node, wrangler, config, env=env, cwd=stage, runner=runner)
        upload_environment = dict(env)
        upload_environment["WRANGLER_OUTPUT_FILE_PATH"] = str(upload_output)
        run_remote_mutation(
            [
                node,
                wrangler,
                "versions",
                "upload",
                "--config",
                config,
                "--strict",
                "--tag",
                RECOVERY_TAG,
                "--message",
                RECOVERY_MESSAGE,
            ],
            env=upload_environment,
            cwd=stage,
            runner=runner,
        )
        try:
            upload_record = _read_remote_mutation_record(upload_output, "version-upload")
            source_version_id = _validated_remote_identifier(upload_record.get("version_id"), "uploaded Worker version ID")
        except AdminRecoveryError as error:
            if str(error) != REMOTE_OUTCOME_UNKNOWN:
                raise
            source_version_id = _recover_uploaded_version_id(
                versions_before,
                _remote_version_ids(node, wrangler, config, env=env, cwd=stage, runner=runner),
            )
        reconcile_remote_readback(
            [node, wrangler, "versions", "view", source_version_id, "--json", "--config", config],
            lambda payload: _validate_version_view(payload, source_version_id, required_secrets),
            env=env,
            cwd=stage,
            runner=runner,
            sleeper=sleeper,
        )

        version_id = migrate_admin_credentials(
            node,
            wrangler,
            config,
            manifest,
            password,
            normalized_seed,
            source_version_id,
            env=env,
            cwd=stage,
            runner=runner,
        )
        reconcile_remote_readback(
            [node, wrangler, "versions", "view", version_id, "--json", "--config", config],
            lambda payload: _validate_version_view(payload, version_id, required_secrets),
            env=env,
            cwd=stage,
            runner=runner,
            sleeper=sleeper,
        )

        deploy_environment = dict(env)
        deploy_environment["WRANGLER_OUTPUT_FILE_PATH"] = str(deploy_output)
        run_remote_mutation(
            [
                node,
                wrangler,
                "versions",
                "deploy",
                f"{version_id}@100%",
                "--yes",
                "--message",
                RECOVERY_MESSAGE,
                "--config",
                config,
            ],
            env=deploy_environment,
            cwd=stage,
            runner=runner,
        )
        try:
            deploy_record = _read_remote_mutation_record(deploy_output, "version-deploy")
            deployment_id = _validated_remote_identifier(deploy_record.get("deployment_id"), "Worker deployment ID")
        except AdminRecoveryError as error:
            if str(error) != REMOTE_OUTCOME_UNKNOWN:
                raise
            status_result = run_remote_mutation(
                [node, wrangler, "deployments", "status", "--json", "--config", config],
                env=env,
                cwd=stage,
                runner=runner,
            )
            if status_result is None or status_result.returncode != 0:
                raise AdminRecoveryError(REMOTE_OUTCOME_UNKNOWN) from error
            deployment_id = _recover_deployment_id(status_result.stdout, version_id)
        reconcile_remote_readback(
            [node, wrangler, "deployments", "status", "--json", "--config", config],
            lambda payload: _validate_deployment_status(payload, deployment_id, version_id),
            env=env,
            cwd=stage,
            runner=runner,
            sleeper=sleeper,
        )
        check_secret_names_at(node, wrangler, config, manifest, env=env, cwd=stage, runner=runner)
        if login_prover is None:
            raise AdminRecoveryError("administrator login proof is unavailable")
        login_prover(config, password, normalized_seed)
        return {
            "source_commit": RECOVERY_RELEASE,
            "toolchain_sha256": TOOLCHAIN_DIGEST,
            "version_id": version_id,
            "deployment_id": deployment_id,
        }
    except BaseException as error:
        operation_error = error
        raise
    finally:
        normalized_seed = ""
        cleanup_error = _remove_recovery_files((upload_output, deploy_output))
        if cleanup_error is not None:
            message = "administrator recovery temporary file cleanup failed"
            if operation_error is None:
                raise AdminRecoveryError(message) from cleanup_error
            if isinstance(operation_error, Exception):
                raise AdminRecoveryError(f"{operation_error}; {message}") from operation_error
            operation_error.add_note(message)


def validate_seed(value):
    normalized = str(value).strip().upper()
    if not SEED_RE.fullmatch(normalized):
        raise AdminRecoveryError("new TOTP seed must be 16-128 Base32 characters")
    # Match the Worker decoder: reject an input that produces no complete byte.
    bits = len(normalized) * 5
    if bits < 8:
        raise AdminRecoveryError("new TOTP seed is invalid")
    return normalized


def validate_password(password):
    if not isinstance(password, str) or len(password) < 16:
        raise AdminRecoveryError("new admin password must be at least 16 characters")
    if len(password) > MAX_ADMIN_PASSWORD_CHARACTERS:
        raise AdminRecoveryError("new admin password must be at most 4096 characters")
    try:
        password.encode("utf-8", "strict")
    except UnicodeError as error:
        raise AdminRecoveryError("new admin password must be valid UTF-8 text") from error
    return password


def password_record(password):
    validate_password(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"pbkdf2_sha256$100000${b64url(salt)}${b64url(digest)}"


def _decode_totp_seed(seed):
    accumulator = 0
    bit_count = 0
    decoded = bytearray()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    for character in validate_seed(seed):
        accumulator = (accumulator << 5) | alphabet.index(character)
        bit_count += 5
        if bit_count >= 8:
            bit_count -= 8
            decoded.append((accumulator >> bit_count) & 0xFF)
            accumulator &= (1 << bit_count) - 1
    return bytes(decoded)


def _totp(seed, timestamp):
    counter = int(timestamp) // 30
    digest = hmac.new(
        _decode_totp_seed(seed),
        counter.to_bytes(8, "big"),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def _recovery_login_settings(config_path):
    try:
        payload = PUBLISHER.read_private_config(config_path, expected_uid=os.geteuid())
        document = json.loads(payload.decode("utf-8", "strict"), object_pairs_hook=_strict_object)
    except (PUBLISHER.LocalPublishError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise AdminRecoveryError("private Wrangler config is invalid") from error
    variables = document.get("vars") if isinstance(document, dict) else None
    username = variables.get("ADMIN_USERNAME") if isinstance(variables, dict) else None
    base_url = variables.get("SUB2API_DEFAULT_BASE_URL") if isinstance(variables, dict) else None
    if not isinstance(username, str) or not username or len(username) > 128 or not isinstance(base_url, str):
        raise AdminRecoveryError("private Wrangler admin login settings are invalid")
    parsed = urllib.parse.urlsplit(base_url)
    try:
        port = parsed.port
    except ValueError as error:
        raise AdminRecoveryError("private Wrangler admin login settings are invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
    ):
        raise AdminRecoveryError("private Wrangler admin login settings are invalid")
    return username, parsed.hostname


def _validate_login_cookie(headers):
    values = [value for name, value in headers if name.lower() == "set-cookie"]
    matching = [value for value in values if value.startswith("sub2api_allow_admin=")]
    if len(matching) != 1:
        return False
    parts = [part.strip() for part in matching[0].split(";")]
    if not re.fullmatch(r"sub2api_allow_admin=[0-9a-f]{64}", parts[0]):
        return False
    attributes = {}
    flags = set()
    for part in parts[1:]:
        if "=" in part:
            name, value = part.split("=", 1)
            normalized_name = name.lower()
            if normalized_name in attributes:
                return False
            attributes[normalized_name] = value
        else:
            normalized_flag = part.lower()
            if normalized_flag in flags:
                return False
            flags.add(normalized_flag)
    return (
        attributes.get("path") == "/allow-ip/admin"
        and attributes.get("samesite", "").lower() == "strict"
        and attributes.get("max-age") == str(ADMIN_SESSION_TTL_SECONDS)
        and "domain" not in attributes
        and {"httponly", "secure"}.issubset(flags)
    )


def _cookie_value(headers):
    values = [value for name, value in headers if name.lower() == "set-cookie"]
    if len(values) != 1:
        raise AdminRecoveryError("administrator login proof failed")
    value = values[0].split(";", 1)[0]
    if not re.fullmatch(r"sub2api_allow_admin=[0-9a-f]{64}", value):
        raise AdminRecoveryError("administrator login proof failed")
    return value


def _pending_login_cookie(headers):
    values = [value for name, value in headers if name.lower() == "set-cookie"]
    if len(values) != 1:
        return False
    parts = [part.strip() for part in values[0].split(";")]
    if not re.fullmatch(r"sub2api_allow_admin=[0-9a-f]{64}", parts[0]):
        return False
    attributes = {}
    flags = set()
    for part in parts[1:]:
        if "=" in part:
            name, value = part.split("=", 1)
            normalized_name = name.lower()
            if normalized_name in attributes:
                return False
            attributes[normalized_name] = value
        else:
            normalized_flag = part.lower()
            if normalized_flag in flags:
                return False
            flags.add(normalized_flag)
    return (
        attributes.get("path") == "/allow-ip/admin"
        and attributes.get("samesite", "").lower() == "strict"
        and attributes.get("max-age") == "300"
        and "domain" not in attributes
        and {"httponly", "secure"}.issubset(flags)
    )


def _build_admin_login_form(username, password, seed, timestamp):
    try:
        form = urllib.parse.urlencode(
            {
                "action": "login",
                "username": username,
                "password": validate_password(password),
                "token": _totp(seed, timestamp),
            }
        ).encode("ascii")
    except (UnicodeError, ValueError) as error:
        raise AdminRecoveryError("administrator login form is invalid") from error
    if len(form) > MAX_ADMIN_LOGIN_FORM_BYTES:
        raise AdminRecoveryError("administrator login form exceeds 32 KiB")
    return form


def prove_admin_login(
    config_path,
    password,
    seed,
    *,
    connection_factory=http.client.HTTPSConnection,
    now=None,
):
    username, hostname = _recovery_login_settings(config_path)
    timestamp = time.time() if now is None else now
    form = urllib.parse.urlencode(
        {
            "action": "login",
            "username": username,
            "password": validate_password(password),
        }
    ).encode("ascii")
    connection = None
    try:
        connection = connection_factory(
            hostname,
            443,
            timeout=10,
            context=ssl.create_default_context(),
        )
        connection.request(
            "POST",
            "/allow-ip/admin",
            body=form,
            headers={
                "Accept": "text/html",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "sub2api-gate-admin-recovery/1",
            },
        )
        response = connection.getresponse()
        response.read(64 * 1024 + 1)
        headers = response.getheaders()
        locations = [value for name, value in headers if name.lower() == "location"]
        if response.status != 303 or locations != ["/allow-ip/admin"] or not _pending_login_cookie(headers):
            raise AdminRecoveryError("administrator login proof failed")
        pending_cookie = _cookie_value(headers)

        connection.request(
            "GET",
            "/allow-ip/admin",
            headers={
                "Accept": "text/html",
                "Cookie": pending_cookie,
                "User-Agent": "sub2api-gate-admin-recovery/1",
            },
        )
        form_page = connection.getresponse()
        form_body = form_page.read(64 * 1024 + 1)
        csrf_match = re.search(rb'name="csrf" value="([0-9a-f]+)"', form_body)
        if form_page.status != 200 or csrf_match is None:
            raise AdminRecoveryError("administrator login proof failed")

        totp_form = urllib.parse.urlencode(
            {
                "action": "login_totp",
                "csrf": csrf_match.group(1).decode("ascii"),
                "token": _totp(seed, timestamp),
            }
        ).encode("ascii")
        connection.request(
            "POST",
            "/allow-ip/admin",
            body=totp_form,
            headers={
                "Accept": "text/html",
                "Content-Type": "application/x-www-form-urlencoded",
                "Cookie": pending_cookie,
                "User-Agent": "sub2api-gate-admin-recovery/1",
            },
        )
        final_response = connection.getresponse()
        final_body = final_response.read(64 * 1024 + 1)
        final_headers = final_response.getheaders()
        final_locations = [value for name, value in final_headers if name.lower() == "location"]
        if (
            len(final_body) > 64 * 1024
            or final_response.status != 303
            or final_locations != ["/allow-ip/admin"]
            or not _validate_login_cookie(final_headers)
        ):
            raise AdminRecoveryError("administrator login proof failed")
    except (OSError, http.client.HTTPException, ssl.SSLError) as error:
        raise AdminRecoveryError("administrator login proof failed") from error
    finally:
        form = b""
        if connection is not None:
            connection.close()


def run_recovery_candidate(
    password,
    seed,
    node,
    home,
    private_config,
    *,
    apply,
    runner=subprocess.run,
    login_prover=prove_admin_login,
):
    spec = PUBLISHER.ReleaseSpec(RECOVERY_RELEASE, "--forbid-totp-rotation-staging")
    env = environment(home, node)
    with tempfile.TemporaryDirectory(prefix="sub2api-worker-admin-recovery-") as temporary:
        stage = pathlib.Path(temporary) / "release"
        try:
            PUBLISHER.stage_release(ROOT, stage, spec, runner=runner)
        except PUBLISHER.LocalPublishError as error:
            raise AdminRecoveryError("administrator recovery source gate failed") from error
        try:
            PUBLISHER.overlay_reviewed_toolchain(ROOT, stage)
            PUBLISHER.copy_private_config(
                private_config,
                stage / PUBLISHER.PRIVATE_CONFIG_RELATIVE,
                expected_uid=os.geteuid(),
            )
            PUBLISHER.run_publish_plan(
                stage,
                spec,
                node,
                home,
                apply=False,
                runner=runner,
            )
            if apply:
                return publish_recovery_version(
                    stage,
                    password,
                    seed,
                    node,
                    env=env,
                    runner=runner,
                    login_prover=login_prover,
                )
            return None
        except PUBLISHER.LocalPublishError as error:
            raise AdminRecoveryError("administrator recovery candidate gate failed") from error
        finally:
            try:
                PUBLISHER.remove_stage(ROOT, stage, runner=runner)
            except PUBLISHER.LocalPublishError as error:
                raise AdminRecoveryError("administrator recovery worktree cleanup failed") from error


def recover(password, seed, node, *, home, private_config=CONFIG, runner=subprocess.run, login_prover=prove_admin_login):
    return run_recovery_candidate(
        password,
        seed,
        node,
        home,
        private_config,
        apply=True,
        runner=runner,
        login_prover=login_prover,
    )


def _validate_private_inputs(password, seed):
    validate_password(password)
    validate_seed(seed)


def main(
    argv=None,
    *,
    runner=subprocess.run,
    input_func=input,
    getpass_func=getpass.getpass,
    tty_streams=None,
    login_prover=prove_admin_login,
):
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("check",), nargs="?")
    parser.add_argument("--apply", action="store_true", help="replace the administrator password and canonical TOTP seed after private confirmation")
    parser.add_argument(
        "--password-file",
        type=pathlib.Path,
        help="absolute mode-0600 file containing the new administrator password as a single line",
    )
    parser.add_argument(
        "--totp-seed-file",
        type=pathlib.Path,
        help="absolute mode-0600 file containing the new administrator TOTP Base32 seed as a single line",
    )
    parser.add_argument("--node", type=pathlib.Path, default=NODE)
    parser.add_argument("--home", type=pathlib.Path, default=pathlib.Path(os.environ.get("HOME", "")))
    parser.add_argument("--wrangler-config", type=pathlib.Path, default=CONFIG)
    arguments = parser.parse_args(argv)
    if arguments.mode == "check" and arguments.apply:
        parser.error("'check' cannot be combined with --apply")
    if (arguments.password_file is None) != (arguments.totp_seed_file is None):
        parser.error("--password-file and --totp-seed-file must be used together")
    if arguments.password_file is not None and not arguments.apply:
        parser.error("--password-file requires --apply")
    try:
        streams = (sys.stdin, sys.stdout, sys.stderr) if tty_streams is None else tty_streams
        if arguments.apply and (os.geteuid() == 0 or not all(stream.isatty() for stream in streams)):
            raise AdminRecoveryError("administrator recovery requires a private local operator TTY")
        try:
            node = arguments.node.resolve(strict=True)
        except OSError as error:
            raise AdminRecoveryError("local Node executable is unavailable") from error
        if not arguments.home.is_absolute():
            raise AdminRecoveryError("local Wrangler OAuth home must be absolute")
        try:
            home = arguments.home.resolve(strict=True)
        except OSError as error:
            raise AdminRecoveryError("local Wrangler OAuth home is unavailable") from error
        if not node.is_file() or not os.access(node, os.X_OK) or not home.is_dir():
            raise AdminRecoveryError("local Node or Wrangler OAuth home is unavailable")
        PUBLISHER.require_private_config(arguments.wrangler_config, expected_uid=os.geteuid())
        if not arguments.apply:
            run_recovery_candidate(
                None,
                None,
                node,
                home,
                arguments.wrangler_config,
                apply=False,
                runner=runner,
                login_prover=login_prover,
            )
            print("administrator recovery candidate check passed; no Worker Secret was read or changed and no version was published")
            return 0
        if input_func("Type RESET ADMIN ACCESS to continue: ") != "RESET ADMIN ACCESS":
            raise AdminRecoveryError("administrator recovery was not confirmed")
        if arguments.password_file is not None:
            password = _read_private_secret_line(
                arguments.password_file,
                expected_uid=os.geteuid(),
                max_characters=MAX_ADMIN_PASSWORD_CHARACTERS,
                label="administrator password file",
            )
            seed = _read_private_secret_line(
                arguments.totp_seed_file,
                expected_uid=os.geteuid(),
                max_characters=MAX_ADMIN_TOTP_SEED_CHARACTERS,
                label="administrator TOTP seed file",
            )
        else:
            password = getpass_func("New administrator password: ")
            if password != getpass_func("Confirm new administrator password: "):
                raise AdminRecoveryError("new administrator passwords do not match")
            seed = getpass_func("New administrator TOTP Base32 seed: ")
            if seed != getpass_func("Confirm new administrator TOTP Base32 seed: "):
                raise AdminRecoveryError("new administrator TOTP seeds do not match")
        _validate_private_inputs(password, seed)
        try:
            run_recovery_candidate(
                password,
                seed,
                node,
                home,
                arguments.wrangler_config,
                apply=True,
                runner=runner,
                login_prover=login_prover,
            )
        finally:
            password = ""
            seed = ""
        print("administrator recovery completed; exact version and deployment readback plus a fresh administrator login proof passed")
        return 0
    except (AdminRecoveryError, PUBLISHER.LocalPublishError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
