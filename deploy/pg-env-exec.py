#!/usr/bin/env python3
import ipaddress
import os
import pathlib
import sys
import urllib.parse


LIBPQ_ENVIRONMENT_NAMES = {
    "PGAPPNAME",
    "PGCHANNELBINDING",
    "PGCONNECT_TIMEOUT",
    "PGDATABASE",
    "PGHOST",
    "PGHOSTADDR",
    "PGOPTIONS",
    "PGPASSWORD",
    "PGPORT",
    "PGSERVICE",
    "PGSERVICEFILE",
    "PGSSLCERT",
    "PGSSLCRL",
    "PGSSLKEY",
    "PGSSLMODE",
    "PGSSLNEGOTIATION",
    "PGSSLROOTCERT",
    "PGTARGETSESSIONATTRS",
    "PGUSER",
}
URL_ENVIRONMENT_NAMES = {
    "SUB2API_DATABASE_URL",
    "SUB2API_SOURCE_DATABASE_URL",
    "SUB2API_TARGET_DATABASE_URL",
}
ENFORCED_OPTIONS_ENV = "SUB2API_PGOPTIONS"
QUERY_MAPPING = {
    "application_name": "PGAPPNAME",
    "channel_binding": "PGCHANNELBINDING",
    "connect_timeout": "PGCONNECT_TIMEOUT",
    "options": "PGOPTIONS",
    "sslcert": "PGSSLCERT",
    "sslcrl": "PGSSLCRL",
    "sslkey": "PGSSLKEY",
    "sslmode": "PGSSLMODE",
    "sslnegotiation": "PGSSLNEGOTIATION",
    "sslrootcert": "PGSSLROOTCERT",
    "target_session_attrs": "PGTARGETSESSIONATTRS",
}
SSL_MODES = {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}


class ConfigurationError(ValueError):
    pass


def _single_query_values(query):
    parsed = urllib.parse.parse_qs(
        query,
        keep_blank_values=True,
        strict_parsing=True,
        max_num_fields=len(QUERY_MAPPING),
    )
    if set(parsed) - set(QUERY_MAPPING):
        raise ConfigurationError("PostgreSQL URL contains an unsupported option")
    result = {}
    for name, values in parsed.items():
        if len(values) != 1 or not values[0] or "\x00" in values[0]:
            raise ConfigurationError("PostgreSQL URL option is invalid")
        result[name] = values[0]
    return result


def libpq_environment(environment, url_name):
    if url_name not in URL_ENVIRONMENT_NAMES:
        raise ConfigurationError("PostgreSQL URL environment name is not allowed")
    raw_url = environment.get(url_name)
    if not raw_url:
        raise ConfigurationError(f"{url_name} is required")
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except ValueError as exc:
        raise ConfigurationError("PostgreSQL URL is invalid") from exc
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise ConfigurationError("PostgreSQL URL scheme is invalid")
    if not parsed.hostname or parsed.username is None or parsed.password is None:
        raise ConfigurationError("PostgreSQL URL must contain host, user, and password")
    if parsed.fragment or not parsed.path.startswith("/") or parsed.path.count("/") != 1:
        raise ConfigurationError("PostgreSQL URL database path is invalid")
    username = urllib.parse.unquote(parsed.username)
    password = urllib.parse.unquote(parsed.password)
    database = urllib.parse.unquote(parsed.path[1:])
    if not username or not password or not database:
        raise ConfigurationError("PostgreSQL URL credentials or database are empty")
    if any("\x00" in value for value in (username, password, database, parsed.hostname)):
        raise ConfigurationError("PostgreSQL URL contains an invalid value")
    try:
        port = parsed.port or 5432
    except ValueError as exc:
        raise ConfigurationError("PostgreSQL URL port is invalid") from exc

    enforced_options = environment.get(ENFORCED_OPTIONS_ENV, "")
    if len(enforced_options) > 512 or any(
        character in enforced_options for character in ("\x00", "\r", "\n")
    ):
        raise ConfigurationError("enforced PostgreSQL options are invalid")
    result = dict(environment)
    for name in LIBPQ_ENVIRONMENT_NAMES | URL_ENVIRONMENT_NAMES | {ENFORCED_OPTIONS_ENV}:
        result.pop(name, None)
    result.update(
        {
            "PGHOST": parsed.hostname,
            "PGPORT": str(port),
            "PGUSER": username,
            "PGPASSWORD": password,
            "PGDATABASE": database,
        }
    )
    for query_name, value in _single_query_values(parsed.query).items():
        result[QUERY_MAPPING[query_name]] = value
    if enforced_options:
        result["PGOPTIONS"] = " ".join(
            value for value in (result.get("PGOPTIONS", ""), enforced_options) if value
        )
    ssl_mode = result.get("PGSSLMODE")
    if ssl_mode is not None and ssl_mode not in SSL_MODES:
        raise ConfigurationError("PostgreSQL sslmode is invalid")
    try:
        is_loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        is_loopback = False
    if is_loopback:
        if ssl_mode != "disable":
            raise ConfigurationError(
                "loopback PostgreSQL URLs must explicitly use sslmode=disable"
            )
    else:
        if ssl_mode != "verify-full":
            raise ConfigurationError(
                "non-loopback PostgreSQL URLs must explicitly use sslmode=verify-full"
            )
        root_certificate = result.get("PGSSLROOTCERT")
        if root_certificate != "system" and (
            not root_certificate
            or not pathlib.PurePosixPath(root_certificate).is_absolute()
        ):
            raise ConfigurationError(
                "remote PostgreSQL verify-full requires an explicit absolute sslrootcert"
            )
    connect_timeout = result.get("PGCONNECT_TIMEOUT")
    if connect_timeout is not None:
        if not connect_timeout.isdigit() or not 1 <= int(connect_timeout) <= 60:
            raise ConfigurationError("PostgreSQL connect_timeout is invalid")
    result.setdefault("PGCONNECT_TIMEOUT", "10")
    return result


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2 or args[0] not in URL_ENVIRONMENT_NAMES:
        print(
            f"usage: {pathlib.Path(sys.argv[0]).name} "
            "<SUB2API_DATABASE_URL|SUB2API_SOURCE_DATABASE_URL|"
            "SUB2API_TARGET_DATABASE_URL> <command> [args...]",
            file=sys.stderr,
        )
        return 2
    try:
        child_environment = libpq_environment(os.environ, args[0])
    except ConfigurationError as error:
        print(str(error), file=sys.stderr)
        return 1
    try:
        os.execvpe(args[1], args[1:], child_environment)
    except OSError:
        print("PostgreSQL client command could not be started", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
