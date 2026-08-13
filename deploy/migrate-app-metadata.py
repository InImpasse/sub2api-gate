#!/usr/bin/env python3
import json
import math
import os
import pathlib
import re
import secrets
import stat
import subprocess
import sys
import time


EXPECTED_DATA_ROOT = pathlib.Path("/mnt/data/sub2api-gate")
DATA_ROOT_UID = 0
DATA_ROOT_GID = 0
DATA_ROOT_MODE = 0o700
PRICING_FILENAME = "model_pricing.json"
INSTALL_MARKER_FILENAME = ".installed"
INSTALL_MARKER_CONTENT = b"installed_by=sub2api-gate\n"
MAX_PRICING_BYTES = 8 * 1024 * 1024
MAX_MODELS = 50_000
DEADLINE_SECONDS = 180
APP_UID = 1000
APP_GID = 1000
APP_DIRECTORY_MODE = 0o700
APP_FILE_MODE = 0o600
FORBIDDEN_APP_ENTRIES = ("config.yaml", "logs", "preview", "capture")
PRICING_NUMBER_FIELDS = {
    "input_cost_per_token",
    "input_cost_per_token_priority",
    "output_cost_per_token",
    "output_cost_per_token_priority",
    "cache_creation_input_token_cost",
    "cache_creation_input_token_cost_priority",
    "cache_creation_input_token_cost_above_1hr",
    "cache_read_input_token_cost",
    "cache_read_input_token_cost_priority",
    "long_context_input_cost_multiplier",
    "long_context_output_cost_multiplier",
    "output_cost_per_image",
    "output_cost_per_image_token",
    "input_cost_per_image_token",
}
PRICING_INTEGER_FIELDS = {"long_context_input_token_threshold"}
PRICING_BOOLEAN_FIELDS = {"supports_service_tier", "supports_prompt_caching"}
PRICING_ENUM_FIELDS = {
    "litellm_provider": {
        "anthropic",
        "bedrock",
        "deepseek",
        "gemini",
        "openai",
        "text-completion-openai",
        "vertex_ai-embedding-models",
        "vertex_ai-language-models",
        "volcengine",
    },
    "mode": {
        "audio_speech",
        "audio_transcription",
        "chat",
        "completion",
        "embedding",
        "image_generation",
        "realtime",
        "responses",
    },
}
PRICING_FIELDS = (
    PRICING_NUMBER_FIELDS
    | PRICING_INTEGER_FIELDS
    | PRICING_BOOLEAN_FIELDS
    | set(PRICING_ENUM_FIELDS)
)
BILLABLE_PRICE_FIELDS = {
    "input_cost_per_token",
    "output_cost_per_token",
    "output_cost_per_image",
    "output_cost_per_image_token",
    "input_cost_per_image_token",
}


class MigrationError(RuntimeError):
    pass


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("model pricing contains duplicate keys")
        result[key] = value
    return result


def _validate_pricing_record(record):
    if set(record) - PRICING_FIELDS:
        raise ValueError("model pricing contains an unsupported field")
    if not (set(record) & BILLABLE_PRICE_FIELDS):
        raise ValueError("each model pricing entry must contain billable pricing metadata")

    for field, value in record.items():
        if field in PRICING_NUMBER_FIELDS:
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
                or value > 10**12
            ):
                raise ValueError("model pricing number is outside the allowed range")
            continue
        if field in PRICING_INTEGER_FIELDS:
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= 10**9
            ):
                raise ValueError("model pricing integer is outside the allowed range")
            continue
        if field in PRICING_BOOLEAN_FIELDS:
            if not isinstance(value, bool):
                raise ValueError("model pricing capability must be boolean")
            continue
        if not isinstance(value, str) or value not in PRICING_ENUM_FIELDS[field]:
            raise ValueError("model pricing enum is not approved for Sub2API 0.1.176")


def validate_model_pricing(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_PRICING_BYTES:
        raise ValueError("model pricing file size is invalid")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("model pricing must be UTF-8") from exc
    try:
        document = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("model pricing contains a non-finite number")
            ),
        )
    except json.JSONDecodeError as exc:
        raise ValueError("model pricing is not valid JSON") from exc
    if not isinstance(document, dict) or not document or len(document) > MAX_MODELS:
        raise ValueError("model pricing root must be a bounded non-empty object")
    for model, record in document.items():
        if (
            not isinstance(model, str)
            or not model
            or len(model) > 256
            or re.search(r"[\x00-\x1f\x7f]", model)
        ):
            raise ValueError("model pricing model name is invalid")
        if not isinstance(record, dict) or not record:
            raise ValueError("each model pricing entry must be a non-empty object")
        _validate_pricing_record(record)
    return document


def _read_regular_file(path):
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise MigrationError("model pricing source is unavailable") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > MAX_PRICING_BYTES:
            raise MigrationError("model pricing source must be a bounded regular file")
        chunks = []
        remaining = MAX_PRICING_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_PRICING_BYTES:
            raise MigrationError("model pricing source exceeds the size limit")
        return raw
    finally:
        os.close(descriptor)


def _require_exact_data_root():
    configured = os.environ.get("SUB2API_DATA_ROOT")
    if not configured:
        raise MigrationError("SUB2API_DATA_ROOT is required with --apply")
    configured_path = pathlib.Path(configured)
    if configured_path != EXPECTED_DATA_ROOT:
        raise MigrationError("SUB2API_DATA_ROOT must be /mnt/data/sub2api-gate")
    try:
        root_stat = configured_path.stat(follow_symlinks=False)
        resolved = configured_path.resolve(strict=True)
    except OSError as exc:
        raise MigrationError("SUB2API_DATA_ROOT must already exist") from exc
    if (
        configured_path.is_symlink()
        or not stat.S_ISDIR(root_stat.st_mode)
        or resolved != EXPECTED_DATA_ROOT
    ):
        raise MigrationError("SUB2API_DATA_ROOT must be /mnt/data/sub2api-gate")
    if (
        (root_stat.st_uid, root_stat.st_gid) != (DATA_ROOT_UID, DATA_ROOT_GID)
        or stat.S_IMODE(root_stat.st_mode) != DATA_ROOT_MODE
    ):
        raise MigrationError(
            "SUB2API_DATA_ROOT must be owned by root:root with mode 0700"
        )
    return resolved


def _write_owned_file_at(directory_descriptor, filename, payload, mode):
    temporary = f".{filename}.partial-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(
            temporary,
            flags,
            mode,
            dir_fd=directory_descriptor,
        )
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fchown(descriptor, APP_UID, APP_GID)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary,
            filename,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass


def _verify_owned_file_at(directory_descriptor, filename, mode):
    descriptor = os.open(
        filename,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_descriptor,
    )
    try:
        result = os.fstat(descriptor)
        if (
            not stat.S_ISREG(result.st_mode)
            or (result.st_uid, result.st_gid) != (APP_UID, APP_GID)
            or stat.S_IMODE(result.st_mode) != mode
        ):
            raise MigrationError("app metadata permissions are unsafe after write")
    finally:
        os.close(descriptor)


def migrate_app_metadata(deadline):
    data_root = _require_exact_data_root()
    target = data_root / "app"
    try:
        target_stat = target.stat(follow_symlinks=False)
    except OSError as exc:
        raise MigrationError("target app directory must already exist") from exc
    if target.is_symlink() or not stat.S_ISDIR(target_stat.st_mode):
        raise MigrationError("target app path must be a real directory")
    if (
        target.resolve(strict=True) != target
        or (target_stat.st_uid, target_stat.st_gid) != (APP_UID, APP_GID)
        or stat.S_IMODE(target_stat.st_mode) != APP_DIRECTORY_MODE
    ):
        raise MigrationError(
            "target app directory must be owned by 1000:1000 with mode 0700"
        )

    directory_flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        directory_descriptor = os.open(target, directory_flags)
    except OSError as exc:
        raise MigrationError("target app directory could not be opened safely") from exc
    try:
        current = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_uid, current.st_gid) != (APP_UID, APP_GID)
            or stat.S_IMODE(current.st_mode) != APP_DIRECTORY_MODE
            or os.listdir(directory_descriptor)
        ):
            raise MigrationError("target app directory must be fresh, empty, and private")
        if time.monotonic() >= deadline:
            raise MigrationError("app metadata migration deadline exceeded")
        print("checkpoint: empty private target app directory verified")

        copy_pricing = os.environ.get("SUB2API_COPY_MODEL_PRICING", "NO")
        if copy_pricing not in {"YES", "NO"}:
            raise MigrationError("SUB2API_COPY_MODEL_PRICING must be YES or NO")
        normalized = None
        if copy_pricing == "YES":
            source_value = os.environ.get("SUB2API_SOURCE_APP_DIR")
            if not source_value:
                raise MigrationError(
                    "SUB2API_SOURCE_APP_DIR is required when pricing copy is enabled"
                )
            try:
                source = pathlib.Path(source_value).resolve(strict=True)
            except OSError as exc:
                raise MigrationError("source app directory is unavailable") from exc
            if not source.is_dir() or source == target:
                raise MigrationError("source app directory is invalid")
            raw = _read_regular_file(source / PRICING_FILENAME)
            try:
                pricing = validate_model_pricing(raw)
            except ValueError as exc:
                raise MigrationError(str(exc)) from exc
            normalized = (
                json.dumps(
                    pricing,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("ascii")
            if len(normalized) > MAX_PRICING_BYTES:
                raise MigrationError("normalized model pricing exceeds the size limit")
        if time.monotonic() >= deadline:
            raise MigrationError("app metadata migration deadline exceeded")

        created = []
        try:
            if normalized is not None:
                _write_owned_file_at(
                    directory_descriptor,
                    PRICING_FILENAME,
                    normalized,
                    APP_FILE_MODE,
                )
                created.append(PRICING_FILENAME)
            _write_owned_file_at(
                directory_descriptor,
                INSTALL_MARKER_FILENAME,
                INSTALL_MARKER_CONTENT,
                0o400,
            )
            created.append(INSTALL_MARKER_FILENAME)
            os.fsync(directory_descriptor)
        except Exception:
            for filename in reversed(created):
                try:
                    os.unlink(filename, dir_fd=directory_descriptor)
                except FileNotFoundError:
                    pass
            os.fsync(directory_descriptor)
            raise

        if normalized is not None:
            _verify_owned_file_at(
                directory_descriptor, PRICING_FILENAME, APP_FILE_MODE
            )
            print("checkpoint: validated model_pricing.json copied atomically")
        else:
            print("checkpoint: no model pricing copy requested")
        _verify_owned_file_at(
            directory_descriptor, INSTALL_MARKER_FILENAME, 0o400
        )
        print("checkpoint: credential-free .installed marker created atomically")
        return 1 if normalized is not None else 0
    finally:
        os.close(directory_descriptor)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    mode = args[0] if args else "check"
    if len(args) > 1 or mode not in {"check", "--apply", "--target-only-apply"}:
        print(
            f"usage: {pathlib.Path(sys.argv[0]).name} "
            "[check|--apply|--target-only-apply]",
            file=sys.stderr,
        )
        return 2
    print("target app data starts empty")
    print("a credential-free read-only .installed marker is always created")
    print("only an optional validated model_pricing.json can also be copied")
    print("config.yaml, logs, preview, and capture data are explicitly excluded")
    if mode == "check":
        print("check only; no connection was opened and no file was written")
        return 0

    repo_dir = pathlib.Path(__file__).resolve().parents[1]
    subprocess.run([repo_dir / "deploy" / "require-clean-worktree.sh", "check"], check=True)
    if mode == "--apply" and os.environ.get("SUB2API_MIGRATION_WRITES_STOPPED") != "YES":
        raise MigrationError(
            "set SUB2API_MIGRATION_WRITES_STOPPED=YES only after all source writers are stopped"
        )
    copied = migrate_app_metadata(time.monotonic() + DEADLINE_SECONDS)
    print(
        "app metadata migration completed within the 180 second deadline "
        f"({copied} file copied)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MigrationError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
    except subprocess.CalledProcessError:
        print("release worktree gate failed", file=sys.stderr)
        raise SystemExit(1)
