#!/usr/bin/python3 -I
import ipaddress
import importlib.util
import os
import pathlib
import re
import stat
import sys
import urllib.parse

REPO_DIR = pathlib.Path(__file__).resolve().parents[1]

ALL_URL_ENVIRONMENT_NAMES = {
    "SUB2API_DATABASE_URL",
    "SUB2API_SOURCE_DATABASE_URL",
    "SUB2API_TARGET_DATABASE_URL",
}
URL_ENVIRONMENT_NAMES = {
    "SUB2API_DATABASE_URL",
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
PRIVATE_URL_ENVIRONMENT_NAMES = {"SUB2API_TARGET_DATABASE_URL"}
PRIVATE_DOCKER_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
LEGACY_IPV4_COMPONENT = re.compile(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)\Z")
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
LOOPBACK_IDENTITY = "loopback"
TARGET_PRIVATE_HOST = "127.0.0.1"
TARGET_PRIVATE_PORT = 15432
TLS_ENVIRONMENT_NAMES = {
    "OPENSSL_CONF",
    "OPENSSL_ENGINES",
    "OPENSSL_MODULES",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SSLKEYLOGFILE",
}
SAFE_COMMAND_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
PSQL_BINARY = pathlib.Path("/usr/bin/psql")
TRUSTED_FILESYSTEM_ROOT = pathlib.Path("/")
TRUSTED_RELEASE_PARENT = pathlib.Path("/opt")
TRUSTED_RELEASE_ROOT = TRUSTED_RELEASE_PARENT / "sub2api-gate-release"
TRUSTED_CONTROLLER = TRUSTED_RELEASE_ROOT / "deploy" / "pg-env-exec.py"


class ConfigurationError(ValueError):
    pass

def require_trusted_release_path(path, *, expects_directory):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise ConfigurationError('trusted PostgreSQL release path is unavailable') from error
    if (
        not target.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or (expects_directory and not stat.S_ISDIR(metadata.st_mode))
        or (not expects_directory and not stat.S_ISREG(metadata.st_mode))
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ConfigurationError('trusted PostgreSQL release path is unsafe')


def require_production_context():
    if os.geteuid() != 0:
        return
    try:
        source_path = pathlib.Path(__file__).resolve(strict=True)
    except OSError as error:
        raise ConfigurationError('trusted PostgreSQL controller source is unavailable') from error
    if REPO_DIR != TRUSTED_RELEASE_ROOT or source_path != TRUSTED_CONTROLLER:
        raise ConfigurationError('PostgreSQL helper must run from the trusted production release tree')
    for path, expects_directory in (
        (TRUSTED_FILESYSTEM_ROOT, True),
        (TRUSTED_RELEASE_PARENT, True),
        (TRUSTED_RELEASE_ROOT, True),
        (TRUSTED_RELEASE_ROOT / 'deploy', True),
        (TRUSTED_CONTROLLER, False),
        (TRUSTED_RELEASE_ROOT / "deploy" / "private_env.py", False),
    ):
        require_trusted_release_path(path, expects_directory=expects_directory)


def _validate_percent_encoding(value):
    index = 0
    while True:
        index = value.find("%", index)
        if index < 0:
            return
        if (
            index + 2 >= len(value)
            or value[index + 1] not in HEX_DIGITS
            or value[index + 2] not in HEX_DIGITS
        ):
            raise ConfigurationError("PostgreSQL URL percent encoding is invalid")
        index += 3


def _strict_unquote(value):
    _validate_percent_encoding(value)
    try:
        return urllib.parse.unquote(value, encoding="utf-8", errors="strict")
    except UnicodeError as error:
        raise ConfigurationError("PostgreSQL URL percent encoding is invalid") from error


def _legacy_ipv4_address(host):
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(
        LEGACY_IPV4_COMPONENT.fullmatch(part) for part in parts
    ):
        return None
    numbers = []
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                numbers.append(int(part[2:], 16))
            elif len(part) > 1 and part.startswith("0"):
                numbers.append(int(part[1:] or "0", 8))
            else:
                numbers.append(int(part, 10))
        except ValueError as error:
            raise ConfigurationError("PostgreSQL URL host is invalid") from error
    limits = {
        1: (0xFFFFFFFF,),
        2: (0xFF, 0xFFFFFF),
        3: (0xFF, 0xFF, 0xFFFF),
        4: (0xFF, 0xFF, 0xFF, 0xFF),
    }[len(numbers)]
    if any(number > limit for number, limit in zip(numbers, limits)):
        raise ConfigurationError("PostgreSQL URL host is invalid")
    if len(numbers) == 1:
        packed = numbers[0]
    elif len(numbers) == 2:
        packed = (numbers[0] << 24) | numbers[1]
    elif len(numbers) == 3:
        packed = (numbers[0] << 24) | (numbers[1] << 16) | numbers[2]
    else:
        packed = (
            (numbers[0] << 24)
            | (numbers[1] << 16)
            | (numbers[2] << 8)
            | numbers[3]
        )
    return ipaddress.IPv4Address(packed)


def _canonical_database_host(host):
    decoded_host = _strict_unquote(host)
    if not decoded_host or any(
        ord(character) <= 0x20
        or ord(character) == 0x7F
        or character in {"/", "\\", "%"}
        for character in decoded_host
    ):
        raise ConfigurationError("PostgreSQL URL host is invalid")
    decoded_host = decoded_host.rstrip(".")
    if not decoded_host:
        raise ConfigurationError("PostgreSQL URL host is invalid")
    try:
        address = ipaddress.ip_address(decoded_host)
    except ValueError:
        address = _legacy_ipv4_address(decoded_host)
    if address is not None:
        mapped_address = getattr(address, "ipv4_mapped", None)
        is_local = (
            address.is_loopback
            or address.is_unspecified
            or (
                mapped_address is not None
                and (mapped_address.is_loopback or mapped_address.is_unspecified)
            )
        )
        return LOOPBACK_IDENTITY if is_local else address.compressed.lower()
    try:
        dns_host = decoded_host.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ConfigurationError("PostgreSQL URL host is invalid") from error
    labels = dns_host.split(".")
    if (
        len(dns_host) > 253
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        )
    ):
        raise ConfigurationError("PostgreSQL URL host is invalid")
    if dns_host == "localhost" or dns_host.endswith(".localhost"):
        return LOOPBACK_IDENTITY
    return dns_host


def _private_source_logical_identity(raw_url):
    try:
        if not isinstance(raw_url, str) or any(
            ord(character) <= 0x20 or ord(character) == 0x7F
            for character in raw_url
        ):
            raise ConfigurationError("source URL is invalid")
        parsed = urllib.parse.urlsplit(raw_url)
        if (
            parsed.scheme not in {"postgres", "postgresql"}
            or parsed.fragment
            or not parsed.hostname
            or "%" in parsed.hostname
            or parsed.username is None
            or parsed.password is None
            or not parsed.path.startswith("/")
            or parsed.path.count("/") != 1
        ):
            raise ConfigurationError("source URL is invalid")
        try:
            port = parsed.port or 5432
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as error:
            raise ConfigurationError("source URL is invalid") from error
        username = _strict_unquote(parsed.username)
        password = _strict_unquote(parsed.password)
        database = _strict_unquote(parsed.path[1:])
        query_values = _single_query_values(parsed.query)
        if (
            not isinstance(address, ipaddress.IPv4Address)
            or not any(address in network for network in PRIVATE_DOCKER_NETWORKS)
            or parsed.hostname != address.compressed
            or port != 5432
            or query_values != {"sslmode": "disable"}
            or len(username.encode("utf-8")) > 63
            or len(database.encode("utf-8")) > 63
            or any(
                not value
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in value
                )
                for value in (username, password, database)
            )
        ):
            raise ConfigurationError("source URL is invalid")
        return (address.compressed, port, database)
    except (TypeError, ValueError, ConfigurationError) as error:
        raise ConfigurationError(
            "source PostgreSQL URL is not a canonical private container endpoint"
        ) from error


def _libpq_logical_identity(parsed_environment):
    return (
        _canonical_database_host(parsed_environment["PGHOST"]),
        int(parsed_environment["PGPORT"]),
        parsed_environment["PGDATABASE"],
    )


def database_logical_identity(raw_url):
    parsed_environment = libpq_environment(
        {"SUB2API_DATABASE_URL": raw_url}, "SUB2API_DATABASE_URL"
    )
    return _libpq_logical_identity(parsed_environment)


def _single_query_values(query):
    _validate_percent_encoding(query)
    try:
        parsed = urllib.parse.parse_qs(
            query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=len(QUERY_MAPPING),
            encoding="utf-8",
            errors="strict",
        )
    except (UnicodeError, ValueError) as error:
        raise ConfigurationError("PostgreSQL URL option is invalid") from error
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
    if not isinstance(raw_url, str) or any(
        ord(character) <= 0x20 or ord(character) == 0x7F for character in raw_url
    ):
        raise ConfigurationError("PostgreSQL URL is invalid")
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
    if "%" in parsed.hostname:
        raise ConfigurationError("PostgreSQL URL host is invalid")
    username = _strict_unquote(parsed.username)
    password = _strict_unquote(parsed.password)
    database = _strict_unquote(parsed.path[1:])
    if not username or not password or not database:
        raise ConfigurationError("PostgreSQL URL credentials or database are empty")
    if any(
        any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        for value in (username, password, database, parsed.hostname)
    ):
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
    for name in tuple(result):
        if (
            name.startswith("PG")
            or name in ALL_URL_ENVIRONMENT_NAMES
            or name in TLS_ENVIRONMENT_NAMES
            or name == ENFORCED_OPTIONS_ENV
        ):
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
    is_loopback = _canonical_database_host(parsed.hostname) == LOOPBACK_IDENTITY
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


def _load_private_environment(path):
    module_path = pathlib.Path(__file__).with_name("private_env.py")
    spec = importlib.util.spec_from_file_location("sub2api_private_env", module_path)
    if spec is None or spec.loader is None:
        raise ConfigurationError("private PostgreSQL environment loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module.read_private_environment(path)
    except Exception as error:
        if error.__class__.__name__ == "PrivateEnvironmentError":
            raise ConfigurationError("private PostgreSQL environment is invalid") from error
        raise


def private_libpq_environment(environment, private_env_path, url_name):
    if url_name not in PRIVATE_URL_ENVIRONMENT_NAMES:
        raise ConfigurationError("private PostgreSQL URL selection is not allowed")
    values = _load_private_environment(private_env_path)
    private_urls = {
        name: values.get(name)
        for name in (
            "SUB2API_SOURCE_DATABASE_URL",
            "SUB2API_TARGET_DATABASE_URL",
            "SUB2API_DATABASE_URL",
        )
    }
    if any(not value for value in private_urls.values()):
        raise ConfigurationError("private PostgreSQL environment is incomplete")
    source_identity = _private_source_logical_identity(
        private_urls["SUB2API_SOURCE_DATABASE_URL"]
    )
    parsed_environments = {}
    identities = {}
    for name in ("SUB2API_TARGET_DATABASE_URL", "SUB2API_DATABASE_URL"):
        raw_url = private_urls[name]
        candidate_environment = dict(environment)
        candidate_environment[name] = raw_url
        parsed_environment = libpq_environment(candidate_environment, name)
        parsed_environments[name] = parsed_environment
        identities[name] = _libpq_logical_identity(parsed_environment)
    target_identity = identities["SUB2API_TARGET_DATABASE_URL"]
    application_identity = identities["SUB2API_DATABASE_URL"]
    if (
        target_identity != application_identity
        or any(
            parsed_environments[name]["PGHOST"] != TARGET_PRIVATE_HOST
            or int(parsed_environments[name]["PGPORT"]) != TARGET_PRIVATE_PORT
            for name in ("SUB2API_TARGET_DATABASE_URL", "SUB2API_DATABASE_URL")
        )
        or source_identity == target_identity
    ):
        raise ConfigurationError("target PostgreSQL identity is invalid")
    return parsed_environments[url_name]


def clean_cli_environment():
    environment = {
        "PATH": SAFE_COMMAND_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    pgoptions = os.environ.get(ENFORCED_OPTIONS_ENV)
    if pgoptions is not None:
        if len(pgoptions) > 512 or any(
            character in pgoptions for character in ("\x00", "\r", "\n")
        ):
            raise ConfigurationError("enforced PostgreSQL options are invalid")
        environment[ENFORCED_OPTIONS_ENV] = pgoptions
    return environment


def postgres_client_command(command):
    if not command or not isinstance(command[0], str) or "\x00" in command[0]:
        raise ConfigurationError("PostgreSQL client command is required")
    if command[0] == "psql":
        return [str(PSQL_BINARY), *command[1:]]
    if pathlib.PurePath(command[0]).is_absolute():
        return list(command)
    raise ConfigurationError("PostgreSQL client command is not allowed")


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) >= 3 and args[0] == "--target-private-env-file":
        try:
            require_production_context()
            command = postgres_client_command(args[2:])
            child_environment = private_libpq_environment(
                clean_cli_environment(), args[1], "SUB2API_TARGET_DATABASE_URL"
            )
        except ConfigurationError as error:
            print(str(error), file=sys.stderr)
            return 1
    else:
        print(
            f"usage: {pathlib.Path(sys.argv[0]).name} "
            "--target-private-env-file ABSOLUTE_PATH <command> [args...]",
            file=sys.stderr,
        )
        return 2
    try:
        os.execve(command[0], command, child_environment)
    except OSError:
        print("PostgreSQL client command could not be started", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
