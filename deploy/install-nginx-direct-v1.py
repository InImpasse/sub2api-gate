#!/usr/bin/env python3
import argparse
import datetime
import fcntl
import glob
import http.client
import os
import pathlib
import re
import shlex
import stat
import subprocess
import sys
import tempfile


REPO_DIR = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_NGINX_ROOT = pathlib.Path("/etc/nginx")
TRUSTED_RELEASE_ROOT = pathlib.Path("/opt/sub2api-gate-release")
CUTOVER_SOURCE_RELATIVE_PATH = pathlib.Path("deploy/install-nginx-direct-v1.py")
RELEASE_GUARD_RELATIVE_PATH = pathlib.Path("deploy/require-clean-worktree.sh")
CANARY_RUNNER_RELATIVE_PATH = pathlib.Path("deploy/run-v1-responses-canary.py")
TRUSTED_RELEASE_DIRECTORIES = (
    pathlib.Path("deploy"),
    pathlib.Path("nginx"),
    pathlib.Path("nginx/snippets"),
)
TRUSTED_RELEASE_FILES = (
    (CUTOVER_SOURCE_RELATIVE_PATH, False),
    (RELEASE_GUARD_RELATIVE_PATH, True),
    (CANARY_RUNNER_RELATIVE_PATH, True),
    (pathlib.Path("nginx/00-connection-upgrade-map.conf"), False),
    (pathlib.Path("nginx/snippets/sub2api-upstream-stable.conf"), False),
    (pathlib.Path("nginx/sub2api-sync-location.conf"), False),
)
NGINX_OPERATION_LOCK_NAME = "nginx-operation.lock"
MAX_CONFIG_BYTES = 2 * 1024 * 1024
HOSTNAME_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
CAPTURE_MARKERS = (
    "response-preview",
    "response_preview",
    "request-capture",
    "request_capture",
    "body_filter_by_lua",
    "log_by_lua",
    "/capture",
    "_capture",
)
CAPTURE_DIRECTIVE_NAMES = frozenset(
    {
        "mirror",
        "mirror_request_body",
        "body_filter_by_lua",
        "body_filter_by_lua_block",
        "log_by_lua",
        "log_by_lua_block",
    }
)
CLOUDFLARE_ONLY_INCLUDE = (
    "include",
    "/etc/nginx/snippets/cloudflare-only.conf",
)
PRODUCTION_COMMAND_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}
UPSTREAM_BLOCK = """upstream sub2api_backend {
    include /etc/nginx/snippets/sub2api-upstream-active.conf;
    keepalive 64;
}

"""
STABLE_UPSTREAM = b"server 127.0.0.1:8080;\n"
DIRECT_LOCATION = """    location ^~ /v1/ {
        include /etc/nginx/snippets/cloudflare-only.conf;
        proxy_pass http://sub2api_backend;
        access_log off;
        error_log /dev/null crit;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Request-ID $request_id;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_cache off;
        proxy_intercept_errors off;
        proxy_connect_timeout 5s;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
"""


class CutoverError(RuntimeError):
    pass


class CutoverUsageError(CutoverError):
    pass


def _require_trusted_release_path(
    path, *, expects_directory, expects_executable, expected_uid
):
    path = pathlib.Path(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CutoverError("trusted production release tree is unavailable") from error
    if (
        not path.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or (expects_directory and not stat.S_ISDIR(metadata.st_mode))
        or (not expects_directory and not stat.S_ISREG(metadata.st_mode))
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (expects_executable and not metadata.st_mode & stat.S_IXUSR)
    ):
        raise CutoverError("trusted production release tree has an unsafe identity")


def require_trusted_release_tree(
    *, repo_dir=None, source_path=None, trusted_root=None, expected_uid=0
):
    repo_dir = pathlib.Path(REPO_DIR if repo_dir is None else repo_dir)
    trusted_root = pathlib.Path(
        TRUSTED_RELEASE_ROOT if trusted_root is None else trusted_root
    )
    if not trusted_root.is_absolute() or repo_dir != trusted_root:
        raise CutoverError("--apply must run from the trusted production release tree")
    try:
        source_path = (
            pathlib.Path(__file__).resolve(strict=True)
            if source_path is None
            else pathlib.Path(source_path).resolve(strict=True)
        )
    except OSError as error:
        raise CutoverError("trusted production release tree is unavailable") from error
    expected_source = trusted_root / CUTOVER_SOURCE_RELATIVE_PATH
    if source_path != expected_source:
        raise CutoverError("Nginx cutover controller is outside the trusted production release tree")

    trusted_entries = (
        (pathlib.Path("/"), True, False),
        (trusted_root.parent, True, False),
        (trusted_root, True, False),
        *(
            (trusted_root / relative_path, True, False)
            for relative_path in TRUSTED_RELEASE_DIRECTORIES
        ),
        *(
            (trusted_root / relative_path, False, expects_executable)
            for relative_path, expects_executable in TRUSTED_RELEASE_FILES
        ),
    )
    for path, expects_directory, expects_executable in trusted_entries:
        _require_trusted_release_path(
            path,
            expects_directory=expects_directory,
            expects_executable=expects_executable,
            expected_uid=expected_uid,
        )


def require_production_apply_context(*, repo_dir=None, streams=None):
    if os.geteuid() != 0:
        raise CutoverError("--apply must run as root")
    if streams is None:
        streams = (sys.stdin, sys.stdout, sys.stderr)
    try:
        private_tty = all(stream.isatty() for stream in streams)
    except (AttributeError, OSError, ValueError):
        private_tty = False
    if not private_tty:
        raise CutoverError("--apply requires a private interactive terminal")
    require_trusted_release_tree(repo_dir=repo_dir)


class RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise CutoverUsageError("Nginx direct /v1 cutover command validation failed")


class Block:
    def __init__(self, header, start, open_index, close_index, parent):
        self.header = header
        self.start = start
        self.open_index = open_index
        self.close_index = close_index
        self.parent = parent


class Directive:
    def __init__(self, text, start, end, parent):
        self.text = text
        self.start = start
        self.end = end
        self.parent = parent


def strip_comments(value):
    output = []
    quote = None
    escaped = False
    comment = False
    for character in value:
        if comment:
            if character == "\n":
                output.append(character)
                comment = False
            continue
        if quote:
            output.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
            output.append(character)
        elif character == "#":
            comment = True
        else:
            output.append(character)
    return "".join(output)


def tokenise(value):
    try:
        return shlex.split(strip_comments(value), comments=False, posix=True)
    except ValueError as error:
        raise CutoverError("Nginx configuration contains an invalid quoted directive") from error


def is_capture_directive(tokens):
    if not tokens:
        return False
    name = tokens[0].lower()
    return name in CAPTURE_DIRECTIVE_NAMES or name.endswith(
        ("_by_lua", "_by_lua_block", "_by_lua_file")
    )


def code_start(raw):
    quote = None
    escaped = False
    comment = False
    for index, character in enumerate(raw):
        if comment:
            if character == "\n":
                comment = False
            continue
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
            return index
        if character == "#":
            comment = True
            continue
        if not character.isspace():
            return index
    return len(raw)


def parse_config(text):
    blocks = []
    directives = []
    stack = []
    statement_start = 0
    quote = None
    escaped = False
    comment = False

    for index, character in enumerate(text):
        if comment:
            if character == "\n":
                comment = False
            continue
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
            continue
        if character == "#":
            comment = True
            continue
        if character == ";":
            raw = text[statement_start:index]
            cleaned = strip_comments(raw).strip()
            if cleaned:
                offset = code_start(raw)
                directives.append(Directive(
                    cleaned,
                    statement_start + offset,
                    index + 1,
                    stack[-1] if stack else None,
                ))
            statement_start = index + 1
            continue
        if character == "{":
            raw = text[statement_start:index]
            cleaned = strip_comments(raw).strip()
            if not cleaned:
                raise CutoverError("Nginx configuration contains a block without a directive")
            offset = code_start(raw)
            absolute_start = statement_start + offset
            line_start = text.rfind("\n", 0, absolute_start) + 1
            start = line_start if not text[line_start:absolute_start].strip() else absolute_start
            block = Block(
                cleaned,
                start,
                index,
                None,
                stack[-1] if stack else None,
            )
            blocks.append(block)
            stack.append(block)
            statement_start = index + 1
            continue
        if character == "}":
            if not stack:
                raise CutoverError("Nginx configuration contains an unmatched closing brace")
            block = stack.pop()
            block.close_index = index
            statement_start = index + 1

    if quote or stack:
        raise CutoverError("Nginx configuration contains an unterminated quote or block")
    if strip_comments(text[statement_start:]).strip():
        raise CutoverError("Nginx configuration ends with an incomplete directive")
    return blocks, directives


def is_server_block(block):
    return tokenise(block.header) == ["server"]


def server_names(server, directives):
    names = []
    for directive in directives:
        if directive.parent is not server:
            continue
        tokens = tokenise(directive.text)
        if tokens and tokens[0] == "server_name":
            names.extend(tokens[1:])
    return names


def is_tls_server(server, directives):
    for directive in directives:
        if directive.parent is not server:
            continue
        tokens = tokenise(directive.text)
        if not tokens:
            continue
        if tokens[0] == "ssl_certificate":
            return True
        if tokens[0] != "listen" or len(tokens) < 2:
            continue
        address = tokens[1].lower()
        if address == "443" or address.endswith(":443") or address.endswith("]:443"):
            return True
    return False


def location_path(block):
    tokens = tokenise(block.header)
    if not tokens or tokens[0] != "location" or len(tokens) < 2:
        return None, None
    if tokens[1] in {"=", "^~", "~", "~*"}:
        if len(tokens) != 3:
            raise CutoverError("Nginx location directive has an unsupported shape")
        return tokens[1], tokens[2]
    if len(tokens) != 2:
        raise CutoverError("Nginx location directive has an unsupported shape")
    return "", tokens[1]


def direct_directives(block, directives):
    return [
        tokenise(directive.text)
        for directive in directives
        if directive.parent is block
    ]


def is_proxying_location(block, directives):
    _, path = location_path(block)
    return path is not None and any(
        tokens and tokens[0] == "proxy_pass"
        for tokens in direct_directives(block, directives)
    )


def has_explicit_cloudflare_gate(block, directives):
    return direct_directives(block, directives).count(
        list(CLOUDFLARE_ONLY_INCLUDE)
    ) == 1


def add_missing_cloudflare_location_gates(text, server, blocks, directives):
    insertions = []
    for block in blocks:
        if (
            block.parent is server
            and is_proxying_location(block, directives)
            and not has_explicit_cloudflare_gate(block, directives)
        ):
            line_start = text.rfind("\n", 0, block.open_index) + 1
            indentation = re.match(
                r"[ \t]*", text[line_start:block.open_index]
            ).group(0)
            trailing_newline = (
                "" if text[block.open_index + 1:block.open_index + 2] == "\n"
                else "\n"
            )
            insertions.append(
                (
                    block.open_index + 1,
                    "\n"
                    f"{indentation}    include "
                    "/etc/nginx/snippets/cloudflare-only.conf;"
                    f"{trailing_newline}",
                )
            )
    for index, insertion in sorted(insertions, reverse=True):
        text = text[:index] + insertion + text[index:]
    return text


def verify_sync_location_config(text):
    blocks, directives = parse_config(text)
    sync_locations = []
    for block in blocks:
        modifier, path = location_path(block)
        if (
            block.parent is None
            and modifier == "="
            and path == "/_sub2api-sync/provision"
        ):
            sync_locations.append(block)
    if len(sync_locations) != 1:
        raise CutoverError("sync location must contain one reviewed provision endpoint")
    sync_location = sync_locations[0]
    sync_directives = direct_directives(sync_location, directives)
    if ["proxy_pass", "http://127.0.0.1:3021/provision"] not in sync_directives:
        raise CutoverError("sync location is not the reviewed provisioning proxy")
    if not has_explicit_cloudflare_gate(sync_location, directives):
        raise CutoverError(
            "sync proxy location must explicitly include the Cloudflare-only gate"
        )


def block_end_with_newline(text, block):
    end = int(block.close_index) + 1
    while end < len(text) and text[end] in " \t\r":
        end += 1
    if end < len(text) and text[end] == "\n":
        end += 1
    return end


def rewrite_direct_v1(text, hostname):
    normalized_hostname = validate_hostname(hostname)
    blocks, directives = parse_config(text)
    servers = [
        block for block in blocks
        if is_server_block(block)
        and is_tls_server(block, directives)
        and normalized_hostname in server_names(block, directives)
    ]
    if len(servers) != 1:
        raise CutoverError("exactly one Nginx server block must match the approved hostname")
    server = servers[0]
    removals = []

    for block in blocks:
        if block.parent is not server:
            continue
        modifier, path = location_path(block)
        if path is None:
            continue
        lowered_header = block.header.lower()
        lowered_body = text[block.open_index + 1:int(block.close_index)].lower()
        if modifier in {"~", "~*"} and "v1" in path.lower():
            raise CutoverError("regex locations that may match /v1 must be removed manually")
        literal_v1 = modifier not in {"~", "~*"} and (
            path == "/v1" or path.startswith("/v1/")
        )
        capture_location = (
            "mirror" in lowered_body
            or any(marker in lowered_header or marker in lowered_body for marker in CAPTURE_MARKERS)
            or ("capture" in path.lower() and (path.startswith("/_") or path.startswith("@")))
        )
        if literal_v1 or capture_location:
            removals.append((block.start, block_end_with_newline(text, block)))

    for directive in directives:
        if directive.parent is not server:
            continue
        tokens = tokenise(directive.text)
        if is_capture_directive(tokens):
            raise CutoverError("server-wide request capture must be removed manually before cutover")

    if any(
        block.parent is server and is_capture_directive(tokenise(block.header))
        for block in blocks
    ):
        raise CutoverError("server-wide request capture must be removed manually before cutover")

    insertion = int(server.close_index)
    replacements = [(start, end, "") for start, end in removals]
    prefix = "" if insertion > 0 and text[insertion - 1] == "\n" else "\n"
    replacements.append((insertion, insertion, prefix + DIRECT_LOCATION))
    rewritten = text
    for start, end, replacement in sorted(replacements, reverse=True):
        rewritten = rewritten[:start] + replacement + rewritten[end:]

    rewritten_blocks, _ = parse_config(rewritten)
    existing_upstreams = [
        block for block in rewritten_blocks
        if block.parent is None
        and tokenise(block.header) == ["upstream", "sub2api_backend"]
    ]
    if not existing_upstreams:
        rewritten = UPSTREAM_BLOCK + rewritten

    rewritten_blocks, rewritten_directives = parse_config(rewritten)
    rewritten_servers = [
        block for block in rewritten_blocks
        if is_server_block(block)
        and is_tls_server(block, rewritten_directives)
        and normalized_hostname in server_names(block, rewritten_directives)
    ]
    if len(rewritten_servers) != 1:
        raise CutoverError("rewritten Nginx configuration lost the approved server")
    rewritten = add_missing_cloudflare_location_gates(
        rewritten,
        rewritten_servers[0],
        rewritten_blocks,
        rewritten_directives,
    )
    verify_rewritten_config(rewritten, normalized_hostname)
    return rewritten


def verify_rewritten_config(text, hostname):
    blocks, directives = parse_config(text)
    servers = [
        block for block in blocks
        if is_server_block(block)
        and is_tls_server(block, directives)
        and hostname in server_names(block, directives)
    ]
    if len(servers) != 1:
        raise CutoverError("rewritten Nginx configuration lost the approved server")
    server = servers[0]
    upstreams = [
        block for block in blocks
        if block.parent is None
        and tokenise(block.header) == ["upstream", "sub2api_backend"]
    ]
    if len(upstreams) != 1:
        raise CutoverError("rewritten Nginx configuration must contain one reviewed Sub2API upstream")
    upstream_directives = [
        tokenise(directive.text)
        for directive in directives
        if directive.parent is upstreams[0]
    ]
    if upstream_directives.count(
        ["include", "/etc/nginx/snippets/sub2api-upstream-active.conf"]
    ) != 1 or upstream_directives.count(["keepalive", "64"]) != 1:
        raise CutoverError("rewritten Sub2API upstream does not use the reviewed active include")
    if any(tokens and tokens[0] == "server" for tokens in upstream_directives):
        raise CutoverError("rewritten Sub2API upstream must not embed an unmanaged server")
    v1_locations = []
    for block in blocks:
        if block.parent is not server:
            continue
        modifier, path = location_path(block)
        if path is not None and modifier not in {"~", "~*"} and (
            path == "/v1" or path.startswith("/v1/")
        ):
            v1_locations.append(block)
    if len(v1_locations) != 1:
        raise CutoverError("rewritten Nginx configuration must contain one /v1 location")
    body = text[v1_locations[0].open_index + 1:int(v1_locations[0].close_index)]
    required = (
        "proxy_pass http://sub2api_backend;",
        "access_log off;",
        "error_log /dev/null crit;",
        "proxy_request_buffering off;",
        "proxy_set_header Connection $connection_upgrade;",
        "proxy_intercept_errors off;",
    )
    if any(value not in body for value in required):
        raise CutoverError("rewritten /v1 location is not the reviewed direct proxy")
    lowered = body.lower()
    if "mirror" in lowered or "3021" in lowered or any(marker in lowered for marker in CAPTURE_MARKERS):
        raise CutoverError("rewritten /v1 location still contains a capture or sync hop")

    for block in blocks:
        if (
            block.parent is server
            and is_proxying_location(block, directives)
            and not has_explicit_cloudflare_gate(block, directives)
        ):
            raise CutoverError(
                "every proxy location must explicitly include the Cloudflare-only gate"
            )

    for block in blocks:
        if block.parent is not server or block is v1_locations[0]:
            continue
        modifier, path = location_path(block)
        if path is None:
            continue
        body = strip_comments(text[block.open_index + 1:int(block.close_index)]).lower()
        header = strip_comments(block.header).lower()
        if "mirror " in body or any(marker in header or marker in body for marker in CAPTURE_MARKERS):
            raise CutoverError("rewritten server still contains a capture location")
    for directive in directives:
        if directive.parent is not server:
            continue
        lowered_directive = strip_comments(directive.text).lower()
        tokens = tokenise(directive.text)
        if is_capture_directive(tokens):
            raise CutoverError("rewritten server still contains a capture directive")
        if tokens and tokens[0] == "include" and any(
            marker in lowered_directive for marker in CAPTURE_MARKERS
        ):
            raise CutoverError("rewritten server still includes a capture configuration")


def validate_hostname(value):
    hostname = str(value or "").strip().lower().rstrip(".")
    if not HOSTNAME_PATTERN.fullmatch(hostname):
        raise CutoverError("approved hostname is invalid")
    return hostname


def is_production_nginx_root(path):
    try:
        return pathlib.Path(path).resolve(strict=False) == DEFAULT_NGINX_ROOT.resolve(
            strict=False
        )
    except (OSError, RuntimeError) as error:
        raise CutoverError("Nginx root is unsafe") from error


def read_regular_file(path, nginx_root, *, production):
    try:
        resolved = path.resolve(strict=True)
        root_resolved = nginx_root.resolve(strict=True)
        file_stat = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise CutoverError("Nginx site configuration is unavailable") from error
    if root_resolved not in resolved.parents or not stat.S_ISREG(file_stat.st_mode):
        raise CutoverError("Nginx site configuration must be a regular file below the Nginx root")
    directory = resolved.parent
    while True:
        validate_managed_directory(
            directory,
            "Nginx site configuration directory",
            production=production,
        )
        if directory == root_resolved:
            break
        directory = directory.parent
    if stat.S_IMODE(file_stat.st_mode) & 0o022:
        raise CutoverError("Nginx site configuration must not be group/world writable")
    if production and file_stat.st_uid != 0:
        raise CutoverError("Nginx site configuration must be owned by root")
    try:
        raw = resolved.read_bytes()
    except OSError as error:
        raise CutoverError("Nginx site configuration could not be read") from error
    if len(raw) > MAX_CONFIG_BYTES:
        raise CutoverError("Nginx site configuration is too large")
    try:
        return resolved, file_stat, raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CutoverError("Nginx site configuration must be UTF-8") from error


def validate_managed_directory(path, label, *, production):
    try:
        directory_stat = path.stat(follow_symlinks=False)
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CutoverError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISDIR(directory_stat.st_mode)
    ):
        raise CutoverError(f"{label} is unsafe")
    expected_uid = 0 if production else os.geteuid()
    if directory_stat.st_uid != expected_uid or stat.S_IMODE(directory_stat.st_mode) & 0o022:
        raise CutoverError(f"{label} has unsafe ownership or permissions")


def ensure_managed_directory(path, label, *, production):
    if path.exists() or path.is_symlink():
        validate_managed_directory(path, label, production=production)
        return
    try:
        path.mkdir(mode=0o700)
    except OSError as error:
        raise CutoverError(f"{label} could not be created") from error
    validate_managed_directory(path, label, production=production)


def validate_managed_file(path, label, *, production):
    try:
        file_stat = path.stat(follow_symlinks=False)
    except OSError as error:
        raise CutoverError(f"{label} is unavailable") from error
    expected_uid = 0 if production else os.geteuid()
    if path.is_symlink() or not stat.S_ISREG(file_stat.st_mode):
        raise CutoverError(f"{label} must be a regular non-symlink file")
    if file_stat.st_uid != expected_uid or stat.S_IMODE(file_stat.st_mode) & 0o022:
        raise CutoverError(f"{label} has unsafe ownership or permissions")
    return file_stat


def validate_managed_file_if_present(path, label, *, production):
    if path.exists() or path.is_symlink():
        return validate_managed_file(path, label, production=production)
    return None


def acquire_nginx_operation_lock(state_root, *, production):
    lock_path = state_root / NGINX_OPERATION_LOCK_NAME
    validate_managed_file_if_present(
        lock_path,
        "Nginx operation lock",
        production=production,
    )
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise CutoverError("Nginx operation lock could not be opened safely") from error
    try:
        descriptor_stat = os.fstat(descriptor)
        path_stat = validate_managed_file(
            lock_path,
            "Nginx operation lock",
            production=production,
        )
        if (
            descriptor_stat.st_dev != path_stat.st_dev
            or descriptor_stat.st_ino != path_stat.st_ino
        ):
            raise CutoverError("Nginx operation lock changed while it was opened")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise CutoverError(
                "another Nginx apply operation is already in progress"
            ) from error
        except OSError as error:
            raise CutoverError("Nginx operation lock could not be acquired") from error
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def release_nginx_operation_lock(descriptor):
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def atomic_write(path, payload, file_stat=None, mode=0o644):
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        data = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        if file_stat is not None:
            os.fchown(descriptor, file_stat.st_uid, file_stat.st_gid)
            os.fchmod(descriptor, stat.S_IMODE(file_stat.st_mode))
        else:
            os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        raise CutoverError("Nginx configuration could not be written atomically") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def command_ok(command, *, visible=False, production=False):
    result = subprocess.run(
        command,
        stdin=None if visible else subprocess.DEVNULL,
        stdout=None if visible else subprocess.DEVNULL,
        stderr=None if visible else subprocess.DEVNULL,
        env=PRODUCTION_COMMAND_ENV if production else None,
        check=False,
    )
    return result.returncode == 0


def validate_active_config_file(path, nginx_root, *, production):
    try:
        resolved = path.resolve(strict=True)
        root_resolved = nginx_root.resolve(strict=True)
        file_stat = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise CutoverError("Nginx configuration tree could not be inspected") from error
    if root_resolved not in resolved.parents or not stat.S_ISREG(file_stat.st_mode):
        raise CutoverError("Nginx configuration tree contains an unsafe entry")
    expected_uid = 0 if production else os.geteuid()
    if file_stat.st_uid != expected_uid or stat.S_IMODE(file_stat.st_mode) & 0o022:
        raise CutoverError("Nginx configuration tree has unsafe permissions")
    directory = resolved.parent
    while True:
        validate_managed_directory(
            directory,
            "Nginx configuration directory",
            production=production,
        )
        if directory == root_resolved:
            break
        directory = directory.parent
    return resolved, file_stat


def verify_no_capture_config(nginx_root, *, production=False):
    nginx_root = pathlib.Path(nginx_root)
    validate_managed_directory(nginx_root, "Nginx root", production=production)
    total = 0
    try:
        root_resolved = nginx_root.resolve(strict=True)
        main_config = nginx_root / "nginx.conf"
        if main_config.exists() or main_config.is_symlink():
            pending = [main_config]
        else:
            # Test fixtures without nginx.conf still model the two conventional
            # active include roots. Production always starts from nginx.conf.
            pending = []
            conf_dir = nginx_root / "conf.d"
            sites_dir = nginx_root / "sites-enabled"
            if conf_dir.is_dir() and not conf_dir.is_symlink():
                pending.extend(conf_dir.glob("*.conf"))
            if sites_dir.is_dir() and not sites_dir.is_symlink():
                pending.extend(sites_dir.iterdir())
    except CutoverError:
        raise
    except OSError as error:
        raise CutoverError("Nginx configuration tree could not be inspected") from error
    inspected = set()
    while pending:
        path = pathlib.Path(pending.pop())
        try:
            resolved, file_stat = validate_active_config_file(path, nginx_root, production=production)
            identity = (file_stat.st_dev, file_stat.st_ino)
            if identity in inspected:
                continue
            inspected.add(identity)
            raw = resolved.read_bytes()
        except OSError as error:
            raise CutoverError("Nginx configuration tree could not be inspected") from error
        total += len(raw)
        if len(raw) > MAX_CONFIG_BYTES or total > 16 * MAX_CONFIG_BYTES:
            raise CutoverError("Nginx configuration tree is too large")
        try:
            source = raw.decode("utf-8")
            cleaned = strip_comments(source).lower()
        except UnicodeDecodeError as error:
            raise CutoverError("Nginx configuration files must be UTF-8") from error
        if any(marker in cleaned for marker in CAPTURE_MARKERS):
            raise CutoverError("Nginx configuration tree still contains mirror or capture directives")

        blocks, directives = parse_config(source)
        if any(is_capture_directive(tokenise(block.header)) for block in blocks) or any(
            is_capture_directive(tokenise(directive.text)) for directive in directives
        ):
            raise CutoverError("Nginx configuration tree still contains mirror or capture directives")
        for directive in directives:
            tokens = tokenise(directive.text)
            if not tokens or tokens[0] != "include":
                continue
            if len(tokens) != 2:
                raise CutoverError("Nginx include directive has an unsupported shape")
            include_value = tokens[1]
            include_path = pathlib.Path(include_value)
            if ".." in include_path.parts:
                raise CutoverError("Nginx include path is unsafe")
            if include_path.is_absolute():
                if nginx_root != DEFAULT_NGINX_ROOT:
                    try:
                        pattern = nginx_root / include_path.relative_to(DEFAULT_NGINX_ROOT)
                    except ValueError:
                        pattern = include_path
                else:
                    pattern = include_path
            else:
                pattern = nginx_root / include_path
            matches = [pathlib.Path(value) for value in glob.glob(str(pattern))]
            if not matches and not glob.has_magic(str(pattern)):
                raise CutoverError("Nginx included configuration is unavailable")
            pending.extend(matches)


def verify_live_direct_v1(nginx_root, site_path, hostname, *, production):
    validate_managed_directory(nginx_root, "Nginx root", production=production)
    _, _, text = read_regular_file(
        pathlib.Path(site_path),
        pathlib.Path(nginx_root),
        production=production,
    )
    verify_no_capture_config(pathlib.Path(nginx_root), production=production)
    verify_rewritten_config(text, validate_hostname(hostname))
    _, _, sync_text = read_regular_file(
        pathlib.Path(nginx_root) / "snippets" / "sub2api-sync-location.conf",
        pathlib.Path(nginx_root),
        production=production,
    )
    verify_sync_location_config(sync_text)


def local_healthcheck():
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=5)
    try:
        connection.request("GET", "/health", headers={"Connection": "close"})
        response = connection.getresponse()
        response.read(4096)
        if not 200 <= response.status < 300:
            raise CutoverError("current Sub2API health check failed")
    except (OSError, http.client.HTTPException) as error:
        raise CutoverError("current Sub2API health check failed") from error
    finally:
        connection.close()


def run_locked_cutover(arguments, *, test_mode, nginx_root, state_root):
    production = not test_mode
    nginx_parent = pathlib.Path("/etc") if production else nginx_root.parent
    validate_managed_directory(
        nginx_parent,
        "Nginx root parent",
        production=production,
    )
    validate_managed_directory(nginx_root, "Nginx root", production=production)
    validate_managed_directory(
        state_root,
        "Nginx state directory",
        production=production,
    )
    validate_managed_file(
        state_root / NGINX_OPERATION_LOCK_NAME,
        "Nginx operation lock",
        production=production,
    )

    hostname = validate_hostname(arguments.server_name)
    site_path = pathlib.Path(arguments.site_config)
    if not site_path.is_absolute():
        raise CutoverError("Nginx site configuration path must be absolute")
    resolved_site, site_stat, original = read_regular_file(
        site_path, nginx_root, production=production
    )
    rewritten = rewrite_direct_v1(original, hostname)

    source_map = REPO_DIR / "nginx" / "00-connection-upgrade-map.conf"
    expected_map = source_map.read_bytes()
    if expected_map != (
        b"map $http_upgrade $connection_upgrade {\n"
        b"    default upgrade;\n"
        b"    ''      '';\n"
        b"}\n"
    ):
        raise CutoverError("tracked Nginx Upgrade map is not the reviewed version")

    if test_mode:
        nginx_bin = pathlib.Path(os.environ["SUB2API_NGINX_BIN"])
        systemctl_bin = pathlib.Path(os.environ["SUB2API_SYSTEMCTL_BIN"])
        canary_runner = pathlib.Path(os.environ["SUB2API_NGINX_CANARY_RUNNER"])
        release_guard = pathlib.Path(os.environ["SUB2API_RELEASE_GUARD"])
    else:
        nginx_bin = pathlib.Path("/usr/sbin/nginx")
        systemctl_bin = pathlib.Path("/usr/bin/systemctl")
        canary_runner = REPO_DIR / "deploy" / "run-v1-responses-canary.py"
        release_guard = REPO_DIR / "deploy" / "require-clean-worktree.sh"
    for executable in (nginx_bin, systemctl_bin, canary_runner, release_guard):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise CutoverError("a required cutover executable is unavailable")

    conf_dir = nginx_root / "conf.d"
    validate_managed_directory(
        conf_dir,
        "Nginx conf.d directory",
        production=production,
    )
    map_target = conf_dir / "00-connection-upgrade-map.conf"
    map_original = None
    map_stat = None
    if map_target.exists() or map_target.is_symlink():
        map_stat = validate_managed_file(
            map_target,
            "existing Nginx Upgrade map",
            production=production,
        )
        map_original = map_target.read_bytes()

    snippets_dir = nginx_root / "snippets"
    validate_managed_directory(
        snippets_dir,
        "Nginx snippets directory",
        production=production,
    )
    source_stable = REPO_DIR / "nginx" / "snippets" / "sub2api-upstream-stable.conf"
    expected_stable = source_stable.read_bytes()
    if expected_stable != STABLE_UPSTREAM:
        raise CutoverError("tracked stable Sub2API upstream is not the reviewed version")
    stable_target = snippets_dir / "sub2api-upstream-active.conf"
    stable_original = None
    stable_stat = None
    if stable_target.exists() or stable_target.is_symlink():
        stable_stat = validate_managed_file(
            stable_target,
            "existing active Sub2API upstream",
            production=production,
        )
        stable_original = stable_target.read_bytes()
        if stable_original != expected_stable:
            raise CutoverError("existing active Sub2API upstream is not stable 127.0.0.1:8080")

    source_sync = REPO_DIR / "nginx" / "sub2api-sync-location.conf"
    expected_sync = source_sync.read_bytes()
    lowered_sync = expected_sync.lower()
    if (
        len(expected_sync) > MAX_CONFIG_BYTES
        or expected_sync.count(b"/_sub2api-sync/provision") != 1
        or b"capture" in lowered_sync
        or b"mirror" in lowered_sync
    ):
        raise CutoverError("tracked sync location is not the reviewed capture-free version")
    try:
        verify_sync_location_config(expected_sync.decode("utf-8"))
    except (UnicodeDecodeError, CutoverError) as error:
        raise CutoverError(
            "tracked sync location is not the reviewed Cloudflare-only proxy"
        ) from error
    sync_target = snippets_dir / "sub2api-sync-location.conf"
    sync_original = None
    sync_stat = None
    if sync_target.exists() or sync_target.is_symlink():
        sync_stat = validate_managed_file(
            sync_target,
            "existing sync location",
            production=production,
        )
        sync_original = sync_target.read_bytes()
        if len(sync_original) > MAX_CONFIG_BYTES:
            raise CutoverError("existing sync location is too large")

    backup_root = state_root / "backups"
    ensure_managed_directory(
        backup_root,
        "Nginx backup root",
        production=production,
    )

    if not command_ok([release_guard, "check"]):
        raise CutoverError("release safety gate failed")
    if not test_mode or os.environ.get("SUB2API_NGINX_SKIP_HEALTH_TEST") != "1":
        local_healthcheck()

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = pathlib.Path(tempfile.mkdtemp(prefix=f"{stamp}-direct-v1-", dir=backup_root))
    os.chmod(backup_dir, 0o700)
    validate_managed_directory(
        backup_dir,
        "Nginx direct cutover backup",
        production=production,
    )
    atomic_write(backup_dir / "site.conf", original, mode=0o600)
    if map_original is not None:
        atomic_write(backup_dir / "connection-map.conf", map_original, mode=0o600)
    else:
        atomic_write(backup_dir / "connection-map.absent", b"", mode=0o600)
    if stable_original is not None:
        atomic_write(backup_dir / "active-upstream.conf", stable_original, mode=0o600)
    else:
        atomic_write(backup_dir / "active-upstream.absent", b"", mode=0o600)
    if sync_original is not None:
        atomic_write(backup_dir / "sync-location.conf", sync_original, mode=0o600)
    else:
        atomic_write(backup_dir / "sync-location.absent", b"", mode=0o600)

    site_changed = False
    map_changed = False
    stable_changed = False
    sync_changed = False
    try:
        atomic_write(resolved_site, rewritten, file_stat=site_stat)
        site_changed = True
        atomic_write(map_target, expected_map, file_stat=map_stat, mode=0o644)
        map_changed = True
        atomic_write(
            stable_target,
            expected_stable,
            file_stat=stable_stat,
            mode=0o644,
        )
        stable_changed = True
        atomic_write(
            sync_target,
            expected_sync,
            file_stat=sync_stat,
            mode=0o644,
        )
        sync_changed = True
        verify_no_capture_config(nginx_root, production=production)
        if not command_ok([nginx_bin, "-t"], production=production):
            raise CutoverError("new Nginx configuration failed syntax validation")
        if not command_ok([systemctl_bin, "reload", "nginx"], production=production):
            raise CutoverError("Nginx reload failed after direct /v1 cutover")
        canary_command = [
            canary_runner,
            "--apply",
            "--url", arguments.verify_url,
            "--model", arguments.model,
            "--approved-hostname", hostname,
        ]
        if not command_ok(canary_command, visible=True, production=production):
            raise CutoverError("end-to-end /v1 canary failed")
    except BaseException:
        if site_changed or map_changed or stable_changed or sync_changed:
            restore_failed = False
            try:
                atomic_write(resolved_site, original, file_stat=site_stat)
                if map_original is None:
                    try:
                        map_target.unlink()
                    except FileNotFoundError:
                        pass
                else:
                    atomic_write(map_target, map_original, file_stat=map_stat)
                if stable_original is None:
                    try:
                        stable_target.unlink()
                    except FileNotFoundError:
                        pass
                else:
                    atomic_write(stable_target, stable_original, file_stat=stable_stat)
                if sync_original is None:
                    try:
                        sync_target.unlink()
                    except FileNotFoundError:
                        pass
                else:
                    atomic_write(sync_target, sync_original, file_stat=sync_stat)
                if not command_ok([nginx_bin, "-t"], production=production):
                    restore_failed = True
                elif not command_ok([systemctl_bin, "reload", "nginx"], production=production):
                    restore_failed = True
            except Exception:
                restore_failed = True
            if restore_failed:
                print("direct /v1 cutover failed and automatic restoration could not be confirmed", file=sys.stderr)
            else:
                print("direct /v1 cutover failed; previous Nginx configuration was restored and reloaded", file=sys.stderr)
        raise

    print("Nginx /v1 path switched to the named Sub2API upstream on stable 127.0.0.1:8080 after syntax, reload, and canary checks")


def install_cutover(arguments):
    test_mode = os.environ.get("SUB2API_NGINX_CUTOVER_TEST_MODE", "0") == "1"
    nginx_root = pathlib.Path(os.environ.get("SUB2API_NGINX_ROOT", DEFAULT_NGINX_ROOT))
    if not nginx_root.is_absolute() or nginx_root == pathlib.Path("/"):
        raise CutoverError("Nginx root is unsafe")
    if test_mode:
        # Test mode selects helper executables from the environment, so it is
        # deliberately unavailable to root even for a temporary Nginx tree.
        if os.geteuid() == 0:
            raise CutoverError("test mode may not run as root")
        if is_production_nginx_root(nginx_root):
            raise CutoverError("test mode may not target the production Nginx root")
    else:
        require_production_apply_context()
    if not test_mode and nginx_root != DEFAULT_NGINX_ROOT:
        raise CutoverError("Nginx root overrides are allowed only in test mode")

    production = not test_mode
    nginx_parent = pathlib.Path("/etc") if production else nginx_root.parent
    validate_managed_directory(
        nginx_parent,
        "Nginx root parent",
        production=production,
    )
    validate_managed_directory(nginx_root, "Nginx root", production=production)

    site_path = pathlib.Path(arguments.site_config)
    if not site_path.is_absolute():
        raise CutoverError("Nginx site configuration path must be absolute")
    _, _, original = read_regular_file(
        site_path,
        nginx_root,
        production=production,
    )
    rewrite_direct_v1(original, validate_hostname(arguments.server_name))
    conf_dir = nginx_root / "conf.d"
    validate_managed_directory(
        conf_dir,
        "Nginx conf.d directory",
        production=production,
    )
    validate_managed_file_if_present(
        conf_dir / "00-connection-upgrade-map.conf",
        "existing Nginx Upgrade map",
        production=production,
    )

    # Validate every existing state path before creating the shared lock state.
    state_root = nginx_root / "sub2api-gate"
    backup_root = state_root / "backups"
    if state_root.exists() or state_root.is_symlink():
        validate_managed_directory(
            state_root,
            "Nginx state directory",
            production=production,
        )
    if backup_root.exists() or backup_root.is_symlink():
        validate_managed_directory(
            backup_root,
            "Nginx backup root",
            production=production,
        )
    validate_managed_file_if_present(
        state_root / NGINX_OPERATION_LOCK_NAME,
        "Nginx operation lock",
        production=production,
    )

    release_guard = (
        pathlib.Path(os.environ["SUB2API_RELEASE_GUARD"])
        if test_mode
        else REPO_DIR / "deploy" / "require-clean-worktree.sh"
    )
    if not release_guard.is_file() or not os.access(release_guard, os.X_OK):
        raise CutoverError("the release safety gate is unavailable")
    if not command_ok([release_guard, "check"]):
        raise CutoverError("release safety gate failed")

    ensure_managed_directory(
        state_root,
        "Nginx state directory",
        production=production,
    )
    lock_descriptor = acquire_nginx_operation_lock(
        state_root,
        production=production,
    )
    try:
        run_locked_cutover(
            arguments,
            test_mode=test_mode,
            nginx_root=nginx_root,
            state_root=state_root,
        )
    finally:
        release_nginx_operation_lock(lock_descriptor)


def parse_arguments(argv):
    parser = RedactedArgumentParser(allow_abbrev=False)
    parser.add_argument("mode", nargs="?", choices=("check",))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--site-config")
    parser.add_argument("--server-name")
    parser.add_argument("--verify-url")
    parser.add_argument("--model")
    arguments = parser.parse_args(argv)
    if arguments.apply and arguments.mode == "check":
        raise CutoverError("check and --apply are mutually exclusive")
    if arguments.apply and not all((
        arguments.site_config,
        arguments.server_name,
        arguments.verify_url,
        arguments.model,
    )):
        raise CutoverError(
            "--apply requires --site-config, --server-name, --verify-url, and --model"
        )
    return arguments


def main(argv=None):
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    if not arguments.apply:
        source_map = REPO_DIR / "nginx" / "00-connection-upgrade-map.conf"
        if not source_map.is_file() or source_map.is_symlink():
            raise CutoverError("tracked Nginx Upgrade map is unavailable")
        print("Nginx direct /v1 cutover check only; no file was read or changed and Nginx was not reloaded")
        return 0
    install_cutover(arguments)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CutoverUsageError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
    except CutoverError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
