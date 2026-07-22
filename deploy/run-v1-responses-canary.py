#!/usr/bin/env python3
import argparse
import contextlib
import decimal
import getpass
import http.client
import ipaddress
import json
import pathlib
import re
import secrets
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass


DEFAULT_URL = "http://127.0.0.1:8081/v1/responses"
RESPONSES_PATH = "/v1/responses"
CONNECT_TIMEOUT_SECONDS = 5
TOTAL_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 512 * 1024
READ_CHUNK_BYTES = 64 * 1024
MAX_API_KEY_BYTES = 512
MAX_MODEL_BYTES = 128
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
COST_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")


class CanaryError(RuntimeError):
    pass


class CanaryUsageError(CanaryError):
    pass


class CanaryDeadlineExceeded(CanaryError):
    pass


class RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise CanaryUsageError("invalid canary command line")


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    hostname: str
    port: int


def valid_hostname(value):
    if not isinstance(value, str) or value != value.lower() or len(value) > 253:
        return False
    if value.startswith(".") or value.endswith(".") or ".." in value:
        return False
    labels = value.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return False
    return all(HOST_LABEL_RE.fullmatch(label) for label in labels)


def normalize_approved_hostnames(values):
    approved = set()
    for value in values:
        if not valid_hostname(value):
            raise CanaryUsageError("approved hostnames must be exact lowercase DNS names")
        approved.add(value)
    return frozenset(approved)


def validate_endpoint(raw_url, approved_hostnames=()):
    if (
        not isinstance(raw_url, str)
        or not raw_url
        or raw_url != raw_url.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7f for character in raw_url)
    ):
        raise CanaryUsageError("invalid canary URL")
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        port = parsed.port
    except ValueError as error:
        raise CanaryUsageError("invalid canary URL") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != RESPONSES_PATH
        or parsed.query
        or parsed.fragment
    ):
        raise CanaryUsageError("canary URL must use the exact /v1/responses endpoint")
    if port is None:
        port = 80 if parsed.scheme == "http" else 443
    if not 1 <= port <= 65535:
        raise CanaryUsageError("invalid canary URL port")

    hostname = parsed.hostname.lower()
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    is_loopback = address is not None and address.is_loopback
    if parsed.scheme == "http":
        if not is_loopback:
            raise CanaryUsageError("plain HTTP canaries are restricted to loopback")
    elif is_loopback or hostname not in approved_hostnames:
        raise CanaryUsageError("HTTPS canary hostname was not explicitly approved")
    return Endpoint(parsed.scheme, hostname, port)


def validate_model(value):
    if (
        not isinstance(value, str)
        or not MODEL_RE.fullmatch(value)
        or len(value.encode("utf-8")) > MAX_MODEL_BYTES
    ):
        raise CanaryUsageError("model identifier is invalid")
    return value


def validate_api_key(value):
    if not isinstance(value, str):
        raise CanaryError("API key input was invalid")
    encoded = value.encode("utf-8")
    if (
        not encoded
        or len(encoded) > MAX_API_KEY_BYTES
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7f for character in value)
    ):
        raise CanaryError("API key input was invalid")
    return value


def _safe_request_id(value):
    value = value.strip() if isinstance(value, str) else ""
    return value if REQUEST_ID_RE.fullmatch(value) else None


def _safe_token_count(value):
    if value is None:
        return None
    if isinstance(value, bool):
        raise CanaryError("canary response metadata was invalid")
    if isinstance(value, str) and len(value) > 32:
        raise CanaryError("canary response metadata was invalid")
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise CanaryError("canary response metadata was invalid") from error
    if str(number) != str(value) or not 0 <= number <= 10**12:
        raise CanaryError("canary response metadata was invalid")
    return number


def _safe_cost(value):
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise CanaryError("canary response metadata was invalid")
    rendered = str(value)
    if len(rendered) > 64 or not COST_RE.fullmatch(rendered):
        raise CanaryError("canary response metadata was invalid")
    try:
        number = decimal.Decimal(rendered)
    except decimal.InvalidOperation as error:
        raise CanaryError("canary response metadata was invalid") from error
    if not number.is_finite() or not decimal.Decimal(0) <= number <= decimal.Decimal("1000000000"):
        raise CanaryError("canary response metadata was invalid")
    return format(number, "f")


def _response_header(response, names):
    for name in names:
        value = response.getheader(name)
        if value not in (None, ""):
            return value
    return None


def _extract_usage_headers(response):
    return (
        _safe_token_count(response.getheader("X-Sub2API-Input-Tokens")),
        _safe_token_count(response.getheader("X-Sub2API-Output-Tokens")),
        _safe_token_count(response.getheader("X-Sub2API-Total-Tokens")),
        _safe_cost(response.getheader("X-Sub2API-Total-Cost")),
        _safe_cost(response.getheader("X-Sub2API-Actual-Cost")),
    )


def _set_response_timeout(response, seconds):
    fp = getattr(response, "fp", None)
    raw = getattr(fp, "raw", None)
    sock = getattr(raw, "_sock", None)
    if sock is not None:
        sock.settimeout(seconds)


def _drain_bounded_response(response, deadline, clock):
    content_length = response.getheader("Content-Length")
    if content_length not in (None, ""):
        try:
            declared_length = int(content_length)
        except (TypeError, ValueError) as error:
            raise CanaryError("canary response length was invalid") from error
        if declared_length < 0 or declared_length > MAX_RESPONSE_BYTES:
            raise CanaryError("canary response exceeded the byte limit")

    bytes_read = 0
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            raise CanaryDeadlineExceeded("canary deadline exceeded")
        _set_response_timeout(response, min(CONNECT_TIMEOUT_SECONDS, remaining))
        chunk = response.read(min(READ_CHUNK_BYTES, MAX_RESPONSE_BYTES + 1 - bytes_read))
        if clock() > deadline:
            raise CanaryDeadlineExceeded("canary deadline exceeded")
        if not chunk:
            return
        if not isinstance(chunk, bytes):
            raise CanaryError("canary response reader returned invalid data")
        bytes_read += len(chunk)
        if bytes_read > MAX_RESPONSE_BYTES:
            raise CanaryError("canary response exceeded the byte limit")


@contextlib.contextmanager
def _hard_deadline(seconds):
    if (
        threading.current_thread() is not threading.main_thread()
        or not hasattr(signal, "setitimer")
        or not hasattr(signal, "ITIMER_REAL")
    ):
        raise CanaryError("strict canary deadline is unavailable")
    previous_delay, previous_interval = signal.setitimer(signal.ITIMER_REAL, 0)
    if previous_delay or previous_interval:
        signal.setitimer(signal.ITIMER_REAL, previous_delay, previous_interval)
        raise CanaryError("another process deadline is already active")
    previous_handler = signal.getsignal(signal.SIGALRM)

    def deadline_handler(_signum, _frame):
        raise CanaryDeadlineExceeded("canary deadline exceeded")

    signal.signal(signal.SIGALRM, deadline_handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def _default_connection_factory(endpoint, timeout):
    if endpoint.scheme == "https":
        return http.client.HTTPSConnection(
            endpoint.hostname,
            endpoint.port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
    return http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=timeout)


def _empty_metadata(status, request_id, latency_ms):
    return {
        "status": status,
        "request_id": request_id,
        "input_tokens": None,
        "output_tokens": None,
        "total_tokens": None,
        "total_cost": None,
        "actual_cost": None,
        "latency_ms": latency_ms,
    }


def sanitize_output_metadata(metadata):
    if not isinstance(metadata, dict):
        raise CanaryError("canary metadata was invalid")
    status = metadata.get("status")
    latency_ms = metadata.get("latency_ms")
    request_id = metadata.get("request_id")
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or not 100 <= status <= 599
        or isinstance(latency_ms, bool)
        or not isinstance(latency_ms, int)
        or not 0 <= latency_ms <= TOTAL_TIMEOUT_SECONDS * 1000 + 1000
        or (
            request_id is not None
            and (
                not isinstance(request_id, str)
                or not REQUEST_ID_RE.fullmatch(request_id)
            )
        )
    ):
        raise CanaryError("canary metadata was invalid")
    return {
        "status": status,
        "request_id": request_id,
        "input_tokens": _safe_token_count(metadata.get("input_tokens")),
        "output_tokens": _safe_token_count(metadata.get("output_tokens")),
        "total_tokens": _safe_token_count(metadata.get("total_tokens")),
        "total_cost": _safe_cost(metadata.get("total_cost")),
        "actual_cost": _safe_cost(metadata.get("actual_cost")),
        "latency_ms": latency_ms,
    }


def perform_canary(endpoint, model, api_key, *, connection_factory=None, clock=time.monotonic):
    connection_factory = connection_factory or _default_connection_factory
    client_request_id = "canary-" + secrets.token_hex(16)
    start = clock()
    deadline = start + TOTAL_TIMEOUT_SECONDS
    connection = None
    response = None
    request_body = bytearray(json.dumps(
        {
            "model": model,
            "input": [{
                "role": "user",
                "content": [{"type": "input_text", "text": "OK"}],
            }],
            "max_output_tokens": 16,
            "stream": False,
        },
        separators=(",", ":"),
    ).encode("utf-8"))
    headers = {
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "sub2api-gate-canary/1",
        "X-Request-ID": client_request_id,
    }
    try:
        with _hard_deadline(TOTAL_TIMEOUT_SECONDS):
            connection = connection_factory(endpoint, CONNECT_TIMEOUT_SECONDS)
            connection.request("POST", RESPONSES_PATH, body=request_body, headers=headers)
            for index in range(len(request_body)):
                request_body[index] = 0
            request_body.clear()
            headers.clear()
            remaining = deadline - clock()
            if remaining <= 0:
                raise CanaryDeadlineExceeded("canary deadline exceeded")
            if getattr(connection, "sock", None) is not None:
                connection.sock.settimeout(min(CONNECT_TIMEOUT_SECONDS, remaining))
            response = connection.getresponse()
            status = int(response.status)
            if not 100 <= status <= 599:
                raise CanaryError("canary response status was invalid")
            request_id = _safe_request_id(
                _response_header(response, ("x-request-id", "request-id"))
            )
            if not 200 <= status <= 299:
                return _empty_metadata(
                    status,
                    request_id,
                    max(0, round((clock() - start) * 1000)),
                )
            _drain_bounded_response(response, deadline, clock)
            usage = _extract_usage_headers(response)
            latency_ms = max(0, round((clock() - start) * 1000))
            return {
                "status": status,
                "request_id": request_id,
                "input_tokens": usage[0],
                "output_tokens": usage[1],
                "total_tokens": usage[2],
                "total_cost": usage[3],
                "actual_cost": usage[4],
                "latency_ms": latency_ms,
            }
    except CanaryError:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
        raise CanaryError("canary transport failed") from None
    finally:
        for index in range(len(request_body)):
            request_body[index] = 0
        request_body.clear()
        headers.clear()
        if response is not None:
            with contextlib.suppress(Exception):
                response.close()
        if connection is not None:
            with contextlib.suppress(Exception):
                connection.close()


def require_clean_worktree():
    repo_dir = pathlib.Path(__file__).resolve().parents[1]
    guard = repo_dir / "deploy" / "require-clean-worktree.sh"
    result = subprocess.run(
        [guard, "check"],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise CanaryError("release safety gate failed")


def parse_arguments(argv):
    if any(
        argument == "--api-key" or argument.startswith("--api-key=")
        for argument in argv
    ):
        raise CanaryUsageError("API keys are accepted only from a private terminal")
    parser = RedactedArgumentParser(
        description="Run a metadata-only synthetic /v1/responses canary.",
        allow_abbrev=False,
    )
    parser.add_argument("mode", nargs="?", choices=("check",))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--model")
    parser.add_argument("--approved-hostname", action="append", default=[])
    arguments = parser.parse_args(argv)
    if arguments.apply and arguments.mode == "check":
        raise CanaryUsageError("check and --apply are mutually exclusive")
    return arguments


def main(
    argv=None,
    *,
    password_reader=getpass.getpass,
    request_runner=perform_canary,
    release_guard=require_clean_worktree,
    stdin=None,
    stdout=None,
    stderr=None,
):
    argv = list(sys.argv[1:] if argv is None else argv)
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    arguments = parse_arguments(argv)
    approved = normalize_approved_hostnames(arguments.approved_hostname)
    endpoint = validate_endpoint(arguments.url, approved)
    if not arguments.apply:
        if arguments.model is not None:
            validate_model(arguments.model)
        print("check only; no API key was read and no network connection was opened", file=stdout)
        return 0
    if arguments.model is None:
        raise CanaryUsageError("--model is required with --apply")
    model = validate_model(arguments.model)
    if not stdin.isatty() or not stderr.isatty():
        raise CanaryError("--apply requires a private interactive terminal")
    try:
        release_guard()
    except CanaryError:
        raise
    except Exception:
        raise CanaryError("release safety gate failed") from None
    try:
        api_key = validate_api_key(password_reader("Sub2API API key: "))
    except CanaryError:
        raise
    except (EOFError, OSError):
        raise CanaryError("API key input was unavailable") from None
    try:
        try:
            metadata = request_runner(endpoint, model, api_key)
        except CanaryError:
            raise
        except Exception:
            raise CanaryError("canary execution failed") from None
    finally:
        api_key = ""
    metadata = sanitize_output_metadata(metadata)
    print(
        json.dumps(metadata, separators=(",", ":"), sort_keys=True, allow_nan=False),
        file=stdout,
    )
    return 0 if 200 <= metadata["status"] <= 299 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CanaryUsageError:
        print("canary command validation failed", file=sys.stderr)
        raise SystemExit(2) from None
    except CanaryError:
        print("canary failed safely; no request or response content was logged", file=sys.stderr)
        raise SystemExit(1) from None
    except KeyboardInterrupt:
        print("canary interrupted safely; no request or response content was logged", file=sys.stderr)
        raise SystemExit(130) from None
