#!/usr/bin/env python3
import importlib.util
import os
import pathlib
import stat
import subprocess
import sys


REPO_DIR = pathlib.Path(__file__).resolve().parent.parent
PG_ENV_TOOL = REPO_DIR / "deploy" / "pg-env-exec.py"
SOURCE_PG_EXEC = REPO_DIR / "deploy" / "source-postgres-exec.py"
POSTGRES_LOGGING_SQL_PATH = REPO_DIR / "deploy" / "verify-postgres-runtime-logging.sql"
EXPECTED_DATA_ROOT = pathlib.Path("/mnt/data/sub2api-gate")
RUNTIME_PGOPTIONS = (
    "-c default_transaction_read_only=on -c lock_timeout=1000 "
    "-c statement_timeout=5000 -c idle_in_transaction_session_timeout=5000"
)
POSTGRES_LOG_DIRECTORIES = frozenset(
    {"log", "pg_log", "postgresql-log", "postgresql-logs", "postgresql_log"}
)

PRIVACY_SQL = r"""
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
WITH safe_settings AS (
    SELECT
        COUNT(*) FILTER (
            WHERE key = 'risk_control_enabled'
              AND lower(btrim(value)) = 'false'
        ) = 1 AS risk_control_safe,
        COUNT(*) FILTER (
            WHERE key = 'image_storage_config'
              AND value::jsonb = '{"enabled":false}'::jsonb
        ) = 1 AS image_storage_safe,
        COUNT(*) = 2 AS exact_setting_count
    FROM public.settings
    WHERE key IN ('risk_control_enabled', 'image_storage_config')
), safe_trigger AS (
    SELECT COUNT(*) = 1 AS installed
    FROM pg_catalog.pg_trigger
    WHERE tgrelid = to_regclass('public.settings')
      AND tgname = 'enforce_privacy_safe_settings'
      AND NOT tgisinternal
      AND tgenabled = 'O'
      AND tgtype = 31
      AND tgfoid = to_regprocedure('public.enforce_privacy_safe_settings()')
)
SELECT CASE
    WHEN safe_settings.risk_control_safe
     AND safe_settings.image_storage_safe
     AND safe_settings.exact_setting_count
     AND safe_trigger.installed
    THEN 'ok'
    ELSE 'unsafe'
END
FROM safe_settings CROSS JOIN safe_trigger;
ROLLBACK;
"""


def load_postgres_logging_sql():
    try:
        return POSTGRES_LOGGING_SQL_PATH.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise RuntimeError("runtime_privacy_gate_failed") from error


def is_postgres_log_artifact(relative_path, *, is_directory=False):
    lowered_parts = tuple(part.lower() for part in relative_path.parts)
    name = lowered_parts[-1]
    if name == "current_logfiles":
        return True
    if is_directory:
        return name in POSTGRES_LOG_DIRECTORIES
    if name.endswith(".log"):
        return True
    if name.startswith("postgresql-") and name.endswith((".csv", ".json")):
        return True
    return any(part in POSTGRES_LOG_DIRECTORIES for part in lowered_parts[:-1])


def verify_no_postgres_log_artifacts(environment):
    configured_root = environment.get("SUB2API_DATA_ROOT", "")
    if configured_root != str(EXPECTED_DATA_ROOT):
        raise RuntimeError("runtime_privacy_gate_failed")
    try:
        root_stat = EXPECTED_DATA_ROOT.stat(follow_symlinks=False)
        resolved_root = EXPECTED_DATA_ROOT.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("runtime_privacy_gate_failed") from error
    if (
        EXPECTED_DATA_ROOT.is_symlink()
        or not stat.S_ISDIR(root_stat.st_mode)
        or resolved_root != EXPECTED_DATA_ROOT
    ):
        raise RuntimeError("runtime_privacy_gate_failed")

    walk_errors = []

    def record_walk_error(error):
        walk_errors.append(error)

    try:
        for directory, directory_names, file_names in os.walk(
            EXPECTED_DATA_ROOT,
            topdown=True,
            onerror=record_walk_error,
            followlinks=False,
        ):
            directory_path = pathlib.Path(directory)
            for name in directory_names:
                candidate = directory_path / name
                relative = candidate.relative_to(EXPECTED_DATA_ROOT)
                if candidate.is_symlink() and is_postgres_log_artifact(
                    relative, is_directory=True
                ):
                    raise RuntimeError("runtime_privacy_gate_failed")
            for name in file_names:
                candidate = directory_path / name
                relative = candidate.relative_to(EXPECTED_DATA_ROOT)
                if is_postgres_log_artifact(relative):
                    raise RuntimeError("runtime_privacy_gate_failed")
    except OSError as error:
        raise RuntimeError("runtime_privacy_gate_failed") from error
    if walk_errors:
        raise RuntimeError("runtime_privacy_gate_failed")


def load_pg_environment_tool():
    spec = importlib.util.spec_from_file_location("pg_env_exec_runtime", PG_ENV_TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_runtime_privacy(
    environment,
    env_file,
    database,
    *,
    source_app_container=None,
    source_app_id=None,
    source_postgres_container=None,
    source_postgres_id=None,
):
    artifact_environment = {"SUB2API_DATA_ROOT": str(EXPECTED_DATA_ROOT)}
    verify_no_postgres_log_artifacts(artifact_environment)
    source_environment = dict(environment)
    source_environment["SUB2API_PGOPTIONS"] = RUNTIME_PGOPTIONS
    psql_arguments = [
        "--no-psqlrc",
        "--tuples-only",
        "--no-align",
        "--quiet",
        "--set",
        "ON_ERROR_STOP=1",
    ]
    if database == "source":
        source_values = (
            source_app_container,
            source_app_id,
            source_postgres_container,
            source_postgres_id,
        )
        if any(not value for value in source_values):
            raise RuntimeError("runtime_privacy_gate_failed")
        for name in tuple(source_environment):
            if name.startswith("PG") or name in {
                "SUB2API_DATABASE_URL",
                "SUB2API_SOURCE_DATABASE_URL",
                "SUB2API_TARGET_DATABASE_URL",
            }:
                source_environment.pop(name, None)
        source_environment["SUB2API_PGOPTIONS"] = RUNTIME_PGOPTIONS
        command = [
            "python3",
            str(SOURCE_PG_EXEC),
            "--env-file",
            str(env_file),
            "--source-app-container",
            source_app_container,
            "--source-app-id",
            source_app_id,
            "--source-postgres-container",
            source_postgres_container,
            "--source-postgres-id",
            source_postgres_id,
            "--source-app-state",
            "running",
            "psql",
            *psql_arguments,
        ]
        child_environment = source_environment
        process_timeout = 45
    elif database == "target":
        pg_env = load_pg_environment_tool()
        child_environment = pg_env.private_libpq_environment(
            source_environment,
            env_file,
            "SUB2API_TARGET_DATABASE_URL",
        )
        command = ["psql", *psql_arguments]
        process_timeout = 8
    else:
        raise RuntimeError("runtime_privacy_gate_failed")
    child_environment["PGAPPNAME"] = "sub2api-gate-runtime-privacy"
    result = subprocess.run(
        command,
        input=PRIVACY_SQL + "\n" + load_postgres_logging_sql(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=child_environment,
        timeout=process_timeout,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != "ok":
        raise RuntimeError("runtime_privacy_gate_failed")
    verify_no_postgres_log_artifacts(artifact_environment)


def usage():
    print(
        "usage: verify-runtime-privacy.py check | "
        "--verify --env-file ABSOLUTE_PATH --database source|target "
        "[--source-app-container NAME --source-app-id FULL_ID "
        "--source-postgres-container NAME --source-postgres-id FULL_ID]",
        file=sys.stderr,
    )


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    mode = arguments[0] if arguments else "check"
    if mode == "check" and arguments not in ([], ["check"]):
        usage()
        return 2
    if mode == "check":
        try:
            if os.environ.get("SUB2API_DATA_ROOT"):
                verify_no_postgres_log_artifacts(os.environ)
        except Exception:
            print("runtime privacy preflight check failed", file=sys.stderr)
            return 1
        print("runtime privacy preflight check passed; no database connection was opened")
        return 0
    if mode != "--verify":
        usage()
        return 2
    values = {}
    remaining = arguments[1:]
    allowed = {
        "--env-file": "env_file",
        "--database": "database",
        "--source-app-container": "source_app_container",
        "--source-app-id": "source_app_id",
        "--source-postgres-container": "source_postgres_container",
        "--source-postgres-id": "source_postgres_id",
    }
    while remaining:
        option = remaining.pop(0)
        if option not in allowed or not remaining or allowed[option] in values:
            usage()
            return 2
        values[allowed[option]] = remaining.pop(0)
    database = values.get("database")
    source_names = (
        "source_app_container",
        "source_app_id",
        "source_postgres_container",
        "source_postgres_id",
    )
    if not values.get("env_file") or not database:
        usage()
        return 2
    env_file = pathlib.Path(values["env_file"])
    if not env_file.is_absolute():
        print("private environment file path must be absolute", file=sys.stderr)
        return 2
    if database not in {"source", "target"} or (
        database == "source" and any(not values.get(name) for name in source_names)
    ) or (database == "target" and any(values.get(name) for name in source_names)):
        usage()
        return 2
    try:
        verify_runtime_privacy(
            os.environ,
            env_file,
            database,
            **{name: values.get(name) for name in source_names},
        )
    except Exception:
        print("runtime privacy verification failed", file=sys.stderr)
        return 1
    print("runtime privacy verification passed; only fixed safety predicates were read")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
