#!/usr/bin/python3 -I
import os
import sys


SAFE_COMMAND_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
DANGEROUS_ENVIRONMENT_NAMES = frozenset({
    "ALL_PROXY",
    "CURL_CA_BUNDLE",
    "FTP_PROXY",
    "GIT_SSL_CAINFO",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NO_PROXY",
    "OPENSSL_CONF",
    "OPENSSL_CONF_INCLUDE",
    "OPENSSL_ENGINES",
    "OPENSSL_MODULES",
    "PYTHONHOME",
    "PYTHONHTTPSVERIFY",
    "PYTHONINSPECT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RANDFILE",
    "REQUESTS_CA_BUNDLE",
    "RSYNC_PROXY",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SSLKEYLOGFILE",
})


def sanitize_privileged_environment(environ=None):
    environ = os.environ if environ is None else environ
    for name in tuple(environ):
        if name.upper() in DANGEROUS_ENVIRONMENT_NAMES:
            environ.pop(name, None)
    environ["PATH"] = SAFE_COMMAND_PATH
    environ["LANG"] = "C"
    environ["LC_ALL"] = "C"


# Clear TLS/OpenSSL configuration before those modules are imported in apply mode.
if __name__ == "__main__" and sys.argv[1:2] == ["--apply"]:
    sanitize_privileged_environment()


import argparse
import contextlib
import fcntl
import getpass
import hashlib
import json
import pathlib
import re
import resource
import secrets
import shutil
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


API_BASE = "https://api.cloudflare.com/client/v4"
API_TIMEOUT_SECONDS = 10
MAX_API_RESPONSE_BYTES = 256 * 1024
MAX_PROC_SWAPS_BYTES = 64 * 1024
IDENTIFIER_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
API_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{20,512}$")
AOP_CA_OUTPUT = pathlib.Path("/etc/nginx/sub2api-gate/aop/client-ca.pem")
AOP_CONTROL_STATE = pathlib.Path(
    "/etc/nginx/sub2api-gate/aop/cloudflare-control-state.json"
)
NGINX_INSTALL_STATE = pathlib.Path("/etc/nginx/sub2api-gate/aop/install-state")
NGINX_ACTIVE_SNIPPET = pathlib.Path(
    "/etc/nginx/snippets/sub2api-aop-active.conf"
)
NGINX_OPERATION_LOCK = pathlib.Path(
    "/etc/nginx/sub2api-gate/nginx-operation.lock"
)
SYSTEM_CA_BUNDLE = pathlib.Path("/etc/ssl/certs/ca-certificates.crt")
OPENSSL_BINARY = pathlib.Path("/usr/bin/openssl")
FINDMNT_BINARY = pathlib.Path("/usr/bin/findmnt")
TRUSTED_RELEASE_ROOT = pathlib.Path("/opt/sub2api-gate-release")
AOP_SOURCE_RELATIVE_PATH = pathlib.Path("deploy/configure-cloudflare-aop.py")
RELEASE_GUARD_RELATIVE_PATH = pathlib.Path("deploy/require-clean-worktree.sh")
AOP_INSTALLER_RELATIVE_PATH = pathlib.Path("deploy/install-nginx-aop.sh")
AOP_OPTIONAL_SNIPPET_RELATIVE_PATH = pathlib.Path(
    "nginx/snippets/sub2api-aop-optional.conf"
)
TRUSTED_RELEASE_DIRECTORIES = (
    pathlib.Path("deploy"),
    pathlib.Path("nginx"),
    pathlib.Path("nginx/snippets"),
)
TRUSTED_RELEASE_FILES = (
    (AOP_SOURCE_RELATIVE_PATH, True),
    (RELEASE_GUARD_RELATIVE_PATH, True),
    (AOP_INSTALLER_RELATIVE_PATH, True),
    (AOP_OPTIONAL_SNIPPET_RELATIVE_PATH, False),
)
PEM_CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----"
PEM_CERTIFICATE_END = "-----END CERTIFICATE-----"
MAX_CONTROL_STATE_BYTES = 4 * 1024
MAX_NGINX_SNIPPET_BYTES = 128 * 1024
ASSOCIATION_POLL_ATTEMPTS = 6
ASSOCIATION_POLL_INTERVAL_SECONDS = 2
CONTROL_STATE_FIELDS = frozenset({
    "version",
    "phase",
    "zone_id",
    "hostname",
    "certificate_id",
    "ca_sha256",
    "policy_sha256",
})
CONTROL_STATE_PHASES = frozenset({
    "upload_in_flight",
    "upload_unknown",
    "uploaded",
    "associate_in_flight",
    "associate_unknown",
    "associated",
})
POLICY_FILES = (
    "deploy/configure-cloudflare-aop.py",
    "deploy/install-nginx-aop.sh",
    "nginx/snippets/sub2api-aop-optional.conf",
)


_NOT_FOUND = object()
_MISSING_RESULT = object()


class AopError(RuntimeError):
    pass

def _require_trusted_release_path(
    path, *, expects_directory, expects_executable, expected_uid
):
    path = pathlib.Path(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AopError("trusted AOP release source is unavailable") from error
    if (
        not path.is_absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or (
            expects_directory
            and not stat.S_ISDIR(metadata.st_mode)
        )
        or (
            not expects_directory
            and not stat.S_ISREG(metadata.st_mode)
        )
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (expects_executable and not metadata.st_mode & stat.S_IXUSR)
    ):
        raise AopError("trusted AOP release source has an unsafe identity")


def require_trusted_release_tree(repo_dir, *, source_path=None, expected_uid=0):
    repo_dir = pathlib.Path(repo_dir)
    trusted_root = pathlib.Path(TRUSTED_RELEASE_ROOT)
    if repo_dir != trusted_root:
        raise AopError("AOP apply must run from the trusted production release tree")
    if not trusted_root.is_absolute():
        raise AopError("trusted AOP release root is invalid")
    try:
        source_path = (
            pathlib.Path(__file__).resolve(strict=True)
            if source_path is None
            else pathlib.Path(source_path).resolve(strict=True)
        )
    except OSError as error:
        raise AopError("trusted AOP controller source is unavailable") from error
    expected_source = trusted_root / AOP_SOURCE_RELATIVE_PATH
    if source_path != expected_source:
        raise AopError("AOP controller source is outside the trusted release tree")

    _require_trusted_release_path(
        trusted_root.parent,
        expects_directory=True,
        expects_executable=False,
        expected_uid=expected_uid,
    )
    _require_trusted_release_path(
        trusted_root,
        expects_directory=True,
        expects_executable=False,
        expected_uid=expected_uid,
    )
    for relative_path in TRUSTED_RELEASE_DIRECTORIES:
        _require_trusted_release_path(
            trusted_root / relative_path,
            expects_directory=True,
            expects_executable=False,
            expected_uid=expected_uid,
        )
    for relative_path, expects_executable in TRUSTED_RELEASE_FILES:
        _require_trusted_release_path(
            trusted_root / relative_path,
            expects_directory=False,
            expects_executable=expects_executable,
            expected_uid=expected_uid,
        )


def require_production_apply_context(repo_dir, *, streams=None):
    repo_dir = pathlib.Path(repo_dir)
    if os.geteuid() != 0 or repo_dir != TRUSTED_RELEASE_ROOT:
        raise AopError(
            "AOP apply requires root from the trusted production release tree"
        )
    if streams is None:
        streams = (sys.stdin, sys.stdout, sys.stderr)
    try:
        stdin, stdout, stderr = streams
        private_tty = stdin.isatty() and stdout.isatty() and stderr.isatty()
    except (AttributeError, OSError, ValueError):
        private_tty = False
    if not private_tty:
        raise AopError("AOP apply requires a private interactive TTY")
    require_trusted_release_tree(repo_dir)

class AopRemoteResultUnknown(AopError):
    """The server may have applied a remote write, but it was not confirmed."""


class AopStateCommitUnknown(AopError):
    """A state replacement happened but its directory fsync was not confirmed."""


class RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        error_type = (
            AopRemoteResultUnknown
            if request.get_method() in {"POST", "PUT", "DELETE"}
            else AopError
        )
        raise error_type("Cloudflare AOP API redirects are not allowed")


def safe_subprocess_environment():
    return {
        "PATH": SAFE_COMMAND_PATH,
        "LANG": "C",
        "LC_ALL": "C",
    }


def build_system_tls_context():
    try:
        metadata = os.stat(SYSTEM_CA_BUNDLE, follow_symlinks=False)
    except OSError as error:
        raise AopError("the fixed system TLS CA bundle is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise AopError("the fixed system TLS CA bundle is not a trusted regular file")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    try:
        context.load_verify_locations(cafile=str(SYSTEM_CA_BUNDLE))
    except (OSError, ssl.SSLError) as error:
        raise AopError("the fixed system TLS CA bundle could not be loaded") from error
    return context


def build_api_opener():
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=build_system_tls_context()),
        RejectRedirectHandler(),
    )


def valid_hostname(value):
    if not isinstance(value, str) or value != value.lower() or len(value) > 253:
        return False
    if value.startswith(".") or value.endswith(".") or ".." in value:
        return False
    labels = value.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return False
    return all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    )


def validate_zone_and_hostname(zone_id, hostname):
    if not IDENTIFIER_RE.fullmatch(zone_id or ""):
        raise AopError("zone id must contain exactly 32 lowercase hexadecimal characters")
    if not valid_hostname(hostname):
        raise AopError("hostname must be a lowercase fully qualified DNS hostname")


class CloudflareAopClient:
    def __init__(self, zone_id, token, opener=None):
        if not IDENTIFIER_RE.fullmatch(zone_id or ""):
            raise AopError("invalid Cloudflare zone id")
        if not isinstance(token, str) or API_TOKEN_RE.fullmatch(token) is None:
            raise AopError("Cloudflare API token has an invalid format")
        self.zone_id = zone_id
        self.token = token
        self.opener = build_api_opener() if opener is None else opener

    @property
    def certificates_path(self):
        return f"/zones/{self.zone_id}/origin_tls_client_auth/hostnames/certificates"

    @property
    def hostnames_path(self):
        return f"/zones/{self.zone_id}/origin_tls_client_auth/hostnames"

    def hostname_path(self, hostname):
        if not valid_hostname(hostname):
            raise AopError("invalid AOP hostname")
        return f"{self.hostnames_path}/{hostname}"

    def request(self, method, path, payload=None, *, allow_not_found=False):
        certificate_delete = re.fullmatch(
            re.escape(self.certificates_path) + r"/[0-9a-f]{32}", path
        )
        hostname_detail = re.fullmatch(
            re.escape(self.hostnames_path) + r"/([a-z0-9.-]+)", path
        )
        hostname_get = (
            method == "GET"
            and hostname_detail is not None
            and valid_hostname(hostname_detail.group(1))
        )
        allowed_request = (
            (method == "POST" and path == self.certificates_path)
            or (method == "PUT" and path == self.hostnames_path)
            or (method == "DELETE" and certificate_delete is not None)
            or hostname_get
        )
        if not allowed_request:
            raise AopError("refusing an unexpected Cloudflare API method or path")
        if allow_not_found and not hostname_get:
            raise AopError("not-found handling is restricted to the fixed hostname GET")
        if method in {"DELETE", "GET"}:
            if payload is not None:
                raise AopError("Cloudflare AOP GET and DELETE requests must not include a body")
            data = None
        else:
            if not isinstance(payload, dict):
                raise AopError("Cloudflare AOP API payload must be a JSON object")
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": "sub2api-gate-aop/1",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            API_BASE + path,
            data=data,
            method=method,
            headers=headers,
        )
        try:
            with self.opener.open(request, timeout=API_TIMEOUT_SECONDS) as response:
                raw = response.read(MAX_API_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            if allow_not_found and error.code == 404:
                error.close()
                return _NOT_FOUND
            if method in {"POST", "PUT", "DELETE"} and (
                error.code >= 500 or error.code == 408
            ):
                raise AopRemoteResultUnknown(
                    "Cloudflare AOP remote write result is unknown"
                ) from error
            raise AopError("Cloudflare AOP API request failed") from error
        except (OSError, urllib.error.URLError) as error:
            if method in {"POST", "PUT", "DELETE"}:
                raise AopRemoteResultUnknown(
                    "Cloudflare AOP remote write result is unknown"
                ) from error
            raise AopError("Cloudflare AOP API request failed") from error
        if len(raw) > MAX_API_RESPONSE_BYTES:
            if method in {"POST", "PUT", "DELETE"}:
                raise AopRemoteResultUnknown(
                    "Cloudflare AOP remote write response exceeded the byte limit"
                )
            raise AopError("Cloudflare AOP API response exceeded the byte limit")
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            if method in {"POST", "PUT", "DELETE"}:
                raise AopRemoteResultUnknown(
                    "Cloudflare AOP remote write returned an invalid response"
                ) from error
            raise AopError("Cloudflare AOP API returned an invalid response") from error
        if not isinstance(parsed, dict) or parsed.get("success") is not True:
            raise AopError("Cloudflare AOP API rejected the request")
        return parsed["result"] if "result" in parsed else _MISSING_RESULT

    def upload_certificate(self, certificate, private_key):
        result = self.request(
            "POST",
            self.certificates_path,
            {"certificate": certificate, "private_key": private_key},
        )
        if result is _MISSING_RESULT:
            raise AopRemoteResultUnknown(
                "Cloudflare AOP upload response omitted its result"
            )
        certificate_id = result.get("id") if isinstance(result, dict) else None
        if not isinstance(certificate_id, str) or not IDENTIFIER_RE.fullmatch(certificate_id):
            raise AopRemoteResultUnknown(
                "Cloudflare AOP upload response omitted a valid certificate id"
            )
        return certificate_id

    def associate_hostname(self, hostname, certificate_id, enabled=True):
        if not valid_hostname(hostname) or not IDENTIFIER_RE.fullmatch(certificate_id or ""):
            raise AopError("invalid AOP hostname association")
        if enabled is not True and enabled is not False and enabled is not None:
            raise AopError("invalid AOP hostname association state")
        result = self.request(
            "PUT",
            self.hostnames_path,
            {"config": [{
                "cert_id": certificate_id,
                "enabled": enabled,
                "hostname": hostname,
            }]},
        )
        if result is _MISSING_RESULT:
            raise AopRemoteResultUnknown(
                "Cloudflare AOP association response omitted its result"
            )
        if not isinstance(result, list) or not any(
            isinstance(item, dict)
            and item.get("cert_id") == certificate_id
            and item.get("hostname") == hostname
            and item.get("enabled") is enabled
            for item in result
        ):
            raise AopRemoteResultUnknown(
                "Cloudflare AOP hostname association response was not conclusive"
            )

    def get_hostname_association(self, hostname):
        if not valid_hostname(hostname):
            raise AopError("invalid AOP hostname")
        result = self.request(
            "GET",
            self.hostname_path(hostname),
            allow_not_found=True,
        )
        if result is _NOT_FOUND:
            return None
        if result is _MISSING_RESULT or not isinstance(result, dict):
            raise AopError("Cloudflare AOP hostname lookup returned an invalid result")
        if result.get("hostname") != hostname:
            raise AopError("Cloudflare AOP hostname lookup returned an invalid identity")
        certificate_id = result.get("cert_id")
        if certificate_id is not None and not IDENTIFIER_RE.fullmatch(
            certificate_id if isinstance(certificate_id, str) else ""
        ):
            raise AopError("Cloudflare AOP hostname lookup returned an invalid certificate id")
        enabled = result.get("enabled")
        if enabled is not True and enabled is not False and enabled is not None:
            raise AopError("Cloudflare AOP hostname lookup returned an invalid enabled state")
        statuses = [
            result[name]
            for name in ("status", "cert_status")
            if name in result
        ]
        if not statuses or any(
            not isinstance(value, str)
            or re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", value) is None
            for value in statuses
        ):
            raise AopError("Cloudflare AOP hostname lookup returned an invalid status")
        if len(set(statuses)) != 1:
            raise AopError("Cloudflare AOP hostname lookup returned conflicting statuses")
        return {
            "hostname": hostname,
            "cert_id": certificate_id,
            "enabled": enabled,
            "status": statuses[0],
        }

    def delete_certificate(self, certificate_id):
        if not IDENTIFIER_RE.fullmatch(certificate_id or ""):
            raise AopError("invalid AOP certificate id")
        self.request(
            "DELETE",
            f"{self.certificates_path}/{certificate_id}",
        )


def is_tmpfs(path, *, findmnt_binary=FINDMNT_BINARY, runner=subprocess.run):
    findmnt_binary = pathlib.Path(findmnt_binary)
    if not findmnt_binary.is_absolute():
        raise AopError("findmnt must use an absolute trusted path")
    try:
        result = runner(
            [
                findmnt_binary,
                "--noheadings",
                "--output",
                "FSTYPE",
                "--target",
                path,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=safe_subprocess_environment(),
        )
    except OSError:
        return False
    return result.returncode == 0 and result.stdout.strip() == "tmpfs"


def require_ephemeral_secret_runtime(swaps_path=pathlib.Path("/proc/swaps")):
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
            raise OSError("core limit was not applied")
    except (OSError, ValueError) as error:
        raise AopError("AOP private-key core-dump protection could not be enforced") from error

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(swaps_path, flags)
        try:
            chunks = []
            remaining = MAX_PROC_SWAPS_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(4096, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise AopError("AOP private-key swap protection could not be verified") from error
    if len(payload) > MAX_PROC_SWAPS_BYTES:
        raise AopError("AOP private-key swap protection could not be verified")
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise AopError("AOP private-key swap protection could not be verified") from error
    if not lines or lines[0].split()[:2] != ["Filename", "Type"]:
        raise AopError("AOP private-key swap protection could not be verified")
    if any(line.strip() for line in lines[1:]):
        raise AopError("AOP private keys require host swap to be disabled")


def run_openssl(arguments, *, openssl_binary=OPENSSL_BINARY, runner=subprocess.run):
    openssl_binary = pathlib.Path(openssl_binary)
    if not openssl_binary.is_absolute():
        raise AopError("OpenSSL must use an absolute trusted path")
    try:
        result = runner(
            [openssl_binary, *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=safe_subprocess_environment(),
        )
    except OSError as error:
        raise AopError("OpenSSL could not generate the AOP certificate material") from error
    if result.returncode != 0:
        raise AopError("OpenSSL could not generate the AOP certificate material")


@contextlib.contextmanager
def certificate_material(
    hostname,
    tmpfs_root=pathlib.Path("/dev/shm"),
    *,
    openssl_binary=OPENSSL_BINARY,
    findmnt_binary=FINDMNT_BINARY,
):
    if not valid_hostname(hostname):
        raise AopError("invalid AOP certificate hostname")
    tmpfs_root = pathlib.Path(tmpfs_root)
    if (
        not tmpfs_root.is_dir()
        or tmpfs_root.is_symlink()
        or not is_tmpfs(tmpfs_root, findmnt_binary=findmnt_binary)
    ):
        raise AopError("AOP private keys require an available tmpfs workspace")
    workspace = pathlib.Path(
        tempfile.mkdtemp(prefix="sub2api-aop-", dir=tmpfs_root)
    )
    os.chmod(workspace, 0o700)
    ca_key = workspace / "ca.key"
    ca_cert = workspace / "ca.pem"
    client_key = workspace / "client.key"
    client_csr = workspace / "client.csr"
    client_cert = workspace / "client.pem"
    client_extensions = workspace / "client-extensions.cnf"
    try:
        client_extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=clientAuth\n"
            f"subjectAltName=DNS:{hostname}\n",
            encoding="ascii",
        )
        run_openssl(
            ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", ca_key],
            openssl_binary=openssl_binary,
        )
        run_openssl([
            "req", "-new", "-x509", "-sha256", "-days", "397",
            "-key", ca_key, "-out", ca_cert,
            "-subj", "/CN=Sub2API Gate AOP CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ], openssl_binary=openssl_binary)
        run_openssl(
            ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", client_key],
            openssl_binary=openssl_binary,
        )
        run_openssl([
            "req", "-new", "-sha256", "-key", client_key, "-out", client_csr,
            "-subj", f"/CN={hostname}",
        ], openssl_binary=openssl_binary)
        run_openssl([
            "x509", "-req", "-sha256", "-days", "397",
            "-in", client_csr, "-CA", ca_cert, "-CAkey", ca_key,
            "-set_serial", f"0x{secrets.token_hex(16)}",
            "-extfile", client_extensions, "-out", client_cert,
        ], openssl_binary=openssl_binary)
        for private_path in (ca_key, client_key):
            os.chmod(private_path, 0o600)
        yield {
            "ca_certificate": ca_cert.read_text(encoding="ascii"),
            "client_certificate": client_cert.read_text(encoding="ascii"),
            "client_private_key": client_key.read_text(encoding="ascii"),
            "workspace": workspace,
        }
    finally:
        try:
            shutil.rmtree(workspace)
        except OSError as error:
            raise AopError("AOP tmpfs private-key cleanup failed") from error
        if workspace.exists():
            raise AopError("AOP tmpfs private-key cleanup was not confirmed")


def require_private_directory(path):
    path = pathlib.Path(path)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise AopError("AOP CA output parent must be an existing absolute directory")
    if path.resolve() != path:
        raise AopError("AOP CA output parent must not traverse symlinks")
    if path.stat().st_mode & 0o077:
        raise AopError("AOP CA output parent must not grant group or other permissions")


def require_trusted_directory(path, *, expected_uid):
    path = pathlib.Path(path)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise AopError("AOP trusted directory must be an existing absolute directory")
    if path.resolve() != path:
        raise AopError("AOP trusted directory must not traverse symlinks")
    metadata = path.stat()
    if metadata.st_uid != expected_uid:
        raise AopError("AOP trusted directory does not have the trusted owner")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AopError("AOP trusted directory must not be group or world writable")


def prepare_ca_output(hostname, configured_path, *, allow_test_output=False):
    del hostname
    output = pathlib.Path(configured_path) if configured_path else AOP_CA_OUTPUT
    if not allow_test_output and output != AOP_CA_OUTPUT:
        raise AopError("AOP CA public certificate must remain at the fixed origin /etc path")
    if allow_test_output:
        require_private_directory(output.parent)
    else:
        nginx_root = AOP_CA_OUTPUT.parents[2]
        require_trusted_directory(nginx_root.parent, expected_uid=0)
        require_trusted_directory(nginx_root, expected_uid=0)
        current = nginx_root
        for component in ("sub2api-gate", "aop"):
            current = current / component
            if not current.exists():
                current.mkdir(mode=0o700)
            require_private_directory(current)
            require_trusted_directory(current, expected_uid=0)
    if output.exists() or output.is_symlink():
        raise AopError("refusing to overwrite an existing AOP CA output")
    return output


def normalize_single_pem_certificate(certificate):
    if not isinstance(certificate, str):
        raise AopError("refusing invalid AOP CA public certificate output")
    normalized = certificate.strip()
    if (
        certificate.count(PEM_CERTIFICATE_BEGIN) != 1
        or certificate.count(PEM_CERTIFICATE_END) != 1
        or not normalized.startswith(PEM_CERTIFICATE_BEGIN + "\n")
        or not normalized.endswith("\n" + PEM_CERTIFICATE_END)
        or "PRIVATE KEY" in normalized
    ):
        raise AopError("AOP CA output must contain exactly one PEM certificate")
    try:
        ssl.PEM_cert_to_DER_cert(normalized)
    except ValueError as error:
        raise AopError("refusing invalid AOP CA public certificate output") from error
    return normalized + "\n"


def write_ca_public_key(output, certificate):
    certificate = normalize_single_pem_certificate(certificate)
    temp_path = output.parent / f".{output.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}"
    output_linked = False
    try:
        descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(certificate)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp_path, output)
        output_linked = True
        temp_path.unlink()
        directory_flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_CLOEXEC"):
            directory_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        directory_descriptor = os.open(output.parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except FileExistsError as error:
        raise AopError("refusing to overwrite an existing AOP CA output") from error
    except OSError as error:
        if output_linked:
            output.unlink(missing_ok=True)
        raise AopError("could not atomically write the AOP CA public certificate") from error
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def certificate_sha256(certificate):
    normalized = normalize_single_pem_certificate(certificate)
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(normalized)).hexdigest()


def read_public_ca_fingerprint(path, *, expected_uid):
    path = pathlib.Path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_CONTROL_STATE_BYTES * 8
        ):
            raise AopError("AOP CA public certificate is not a trusted regular file")
        with os.fdopen(descriptor, "r", encoding="ascii") as handle:
            descriptor = -1
            certificate = handle.read(MAX_CONTROL_STATE_BYTES * 8 + 1)
    except (OSError, UnicodeError) as error:
        raise AopError("AOP CA public certificate could not be read safely") from error
    finally:
        if "descriptor" in locals() and descriptor >= 0:
            os.close(descriptor)
    if len(certificate) > MAX_CONTROL_STATE_BYTES * 8:
        raise AopError("AOP CA public certificate exceeded the byte limit")
    return certificate_sha256(certificate)


def compute_policy_sha256(repo_dir):
    repo_dir = pathlib.Path(repo_dir)
    digest = hashlib.sha256()
    for relative_name in POLICY_FILES:
        path = repo_dir / relative_name
        try:
            metadata = path.stat(follow_symlinks=False)
            payload = path.read_bytes()
        except OSError as error:
            raise AopError("AOP policy inputs could not be read") from error
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise AopError("AOP policy inputs must be regular non-symlink files")
        encoded_name = relative_name.encode("ascii")
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def make_control_state(
    *, phase, zone_id, hostname, certificate_id, ca_sha256, policy_sha256
):
    state = {
        "version": 1,
        "phase": phase,
        "zone_id": zone_id,
        "hostname": hostname,
        "certificate_id": certificate_id,
        "ca_sha256": ca_sha256,
        "policy_sha256": policy_sha256,
    }
    validate_control_state(state)
    return state


def validate_control_state(state):
    if not isinstance(state, dict) or set(state) != CONTROL_STATE_FIELDS:
        raise AopError("AOP control state has an invalid schema")
    if (
        type(state["version"]) is not int
        or state["version"] != 1
        or not isinstance(state["phase"], str)
        or state["phase"] not in CONTROL_STATE_PHASES
    ):
        raise AopError("AOP control state has invalid version or phase")
    validate_zone_and_hostname(state["zone_id"], state["hostname"])
    certificate_id = state["certificate_id"]
    if certificate_id is not None and not IDENTIFIER_RE.fullmatch(
        certificate_id if isinstance(certificate_id, str) else ""
    ):
        raise AopError("AOP control state has an invalid certificate id")
    if state["phase"] not in {"upload_in_flight", "upload_unknown"} \
            and certificate_id is None:
        raise AopError("AOP control state phase requires a certificate id")
    if not SHA256_RE.fullmatch(state["ca_sha256"] or "") \
            or not SHA256_RE.fullmatch(state["policy_sha256"] or ""):
        raise AopError("AOP control state has an invalid fingerprint")
    return state


def _reject_duplicate_json_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AopError("AOP control state has duplicate fields")
        result[key] = value
    return result


def _require_state_parent(path, *, expected_uid):
    path = pathlib.Path(path)
    require_private_directory(path.parent)
    require_trusted_directory(path.parent, expected_uid=expected_uid)


def read_control_state(path, *, expected_uid):
    path = pathlib.Path(path)
    _require_state_parent(path, expected_uid=expected_uid)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > MAX_CONTROL_STATE_BYTES
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise AopError("AOP control state has unsafe ownership or permissions")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read(MAX_CONTROL_STATE_BYTES + 1)
    except AopError:
        raise
    except OSError as error:
        raise AopError("AOP control state is missing or unsafe") from error
    finally:
        if "descriptor" in locals() and descriptor >= 0:
            os.close(descriptor)
    if len(payload) > MAX_CONTROL_STATE_BYTES:
        raise AopError("AOP control state exceeds the 4 KiB limit")
    try:
        state = json.loads(
            payload.decode("ascii"), object_pairs_hook=_reject_duplicate_json_fields
        )
    except AopError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AopError("AOP control state is not strict JSON") from error
    return validate_control_state(state)


def _fsync_directory(path):
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_control_state(path, state, *, expected_uid):
    path = pathlib.Path(path)
    state = validate_control_state(dict(state))
    _require_state_parent(path, expected_uid=expected_uid)
    if path.exists() or path.is_symlink():
        read_control_state(path, expected_uid=expected_uid)
    payload = (
        json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    if len(payload) > MAX_CONTROL_STATE_BYTES:
        raise AopError("AOP control state exceeds the 4 KiB limit")
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}"
    replaced = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        replaced = True
        try:
            _fsync_directory(path.parent)
        except OSError as error:
            raise AopStateCommitUnknown(
                "AOP control state directory fsync was not confirmed"
            ) from error
    except AopStateCommitUnknown:
        raise
    except OSError as error:
        raise AopError("AOP control state could not be written atomically") from error
    finally:
        if not replaced:
            temporary.unlink(missing_ok=True)
    return state


def remove_local_control_artifacts(state_path, ca_output):
    for path in (pathlib.Path(state_path), pathlib.Path(ca_output)):
        if not path.exists() and not path.is_symlink():
            continue
        try:
            metadata = os.stat(path, follow_symlinks=False)
        except OSError as error:
            raise AopError("AOP local cleanup could not validate an artifact") from error
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AopError("AOP local cleanup refused an unsafe artifact")
        path.unlink()
    _fsync_directory(pathlib.Path(state_path).parent)


def require_new_control_state(path, *, expected_uid):
    path = pathlib.Path(path)
    _require_state_parent(path, expected_uid=expected_uid)
    if path.exists() or path.is_symlink():
        state = read_control_state(path, expected_uid=expected_uid)
        raise AopError(
            f"AOP control state already exists in phase {state['phase']}; "
            "refusing a second upload"
        )


def require_no_installed_aop_conflict(*, expected_uid=0):
    for path, label in (
        (NGINX_INSTALL_STATE, "Nginx AOP install state"),
        (NGINX_ACTIVE_SNIPPET, "active Nginx AOP snippet"),
    ):
        if path.is_symlink():
            raise AopError(f"{label} is unsafe")
    if NGINX_INSTALL_STATE.exists():
        raise AopError(
            "existing Nginx AOP install state must be retired before uploading a new CA"
        )
    if NGINX_ACTIVE_SNIPPET.exists():
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(NGINX_ACTIVE_SNIPPET, flags)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != expected_uid
                or stat.S_IMODE(metadata.st_mode) & 0o022
                or metadata.st_size > MAX_NGINX_SNIPPET_BYTES
            ):
                raise AopError("active Nginx AOP snippet is unsafe")
            with os.fdopen(descriptor, "r", encoding="ascii") as handle:
                descriptor = -1
                active = handle.read(MAX_NGINX_SNIPPET_BYTES + 1)
        except (OSError, UnicodeError) as error:
            raise AopError("active Nginx AOP snippet could not be inspected") from error
        finally:
            if "descriptor" in locals() and descriptor >= 0:
                os.close(descriptor)
        if len(active) > MAX_NGINX_SNIPPET_BYTES:
            raise AopError("active Nginx AOP snippet exceeded the byte limit")
        if "ssl_verify_client optional;" in active or "ssl_verify_client on;" in active:
            raise AopError(
                "active Nginx AOP configuration must not be overwritten with a new CA"
            )


def _state_with_phase(state, phase, certificate_id=None):
    updated = dict(state)
    updated["phase"] = phase
    if certificate_id is not None:
        updated["certificate_id"] = certificate_id
    return validate_control_state(updated)


def _mark_unknown(state_path, state, phase, *, expected_uid, cause):
    unknown = _state_with_phase(state, phase)
    try:
        write_control_state(state_path, unknown, expected_uid=expected_uid)
    except Exception as state_error:
        raise AopError(
            "remote AOP state is unknown and the recovery marker could not be confirmed"
        ) from state_error
    raise cause


def upload_aop(
    *,
    zone_id,
    hostname,
    ca_output,
    state_path,
    policy_sha256,
    token_provider,
    opener=None,
    allow_test_output=False,
):
    validate_zone_and_hostname(zone_id, hostname)
    if not SHA256_RE.fullmatch(policy_sha256 or ""):
        raise AopError("invalid AOP policy fingerprint")
    output = prepare_ca_output(
        hostname, ca_output, allow_test_output=allow_test_output
    )
    state_path = pathlib.Path(state_path)
    expected_uid = os.getuid() if allow_test_output else 0
    if not allow_test_output:
        if state_path != AOP_CONTROL_STATE:
            raise AopError("AOP control state must remain at the fixed origin /etc path")
        require_no_installed_aop_conflict()
    require_new_control_state(state_path, expected_uid=expected_uid)

    token = token_provider()
    client = CloudflareAopClient(zone_id, token, opener=opener)
    try:
        existing = client.get_hostname_association(hostname)
        if existing is not None:
            raise AopError(
                "an AOP hostname association already exists; refusing to overwrite it"
            )

        outcome = "local_only"
        local_artifacts_created = False
        state = None
        certificate_id = None
        try:
            with certificate_material(hostname) as material:
                ca_certificate = material["ca_certificate"]
                ca_fingerprint = certificate_sha256(ca_certificate)
                write_ca_public_key(output, ca_certificate)
                local_artifacts_created = True
                state = make_control_state(
                    phase="upload_in_flight",
                    zone_id=zone_id,
                    hostname=hostname,
                    certificate_id=None,
                    ca_sha256=ca_fingerprint,
                    policy_sha256=policy_sha256,
                )
                write_control_state(state_path, state, expected_uid=expected_uid)
                outcome = "upload_in_flight"
                try:
                    certificate_id = client.upload_certificate(
                        material["client_certificate"],
                        material["client_private_key"],
                    )
                except AopRemoteResultUnknown as error:
                    outcome = "upload_unknown"
                    _mark_unknown(
                        state_path,
                        state,
                        "upload_unknown",
                        expected_uid=expected_uid,
                        cause=error,
                    )
                except Exception:
                    outcome = "definitive_failure"
                    remove_local_control_artifacts(state_path, output)
                    raise
                state = _state_with_phase(state, "uploaded", certificate_id)
                try:
                    write_control_state(state_path, state, expected_uid=expected_uid)
                except Exception as error:
                    outcome = "upload_unknown"
                    state["phase"] = "upload_unknown"
                    _mark_unknown(
                        state_path,
                        state,
                        "upload_unknown",
                        expected_uid=expected_uid,
                        cause=AopError(
                            "uploaded AOP certificate was not durably recorded"
                        ),
                    )
                outcome = "uploaded"
                material.clear()
        except BaseException as error:
            if outcome == "local_only" and local_artifacts_created:
                remove_local_control_artifacts(state_path, output)
            elif outcome == "uploaded" and state is not None:
                state["phase"] = "upload_unknown"
                _mark_unknown(
                    state_path,
                    state,
                    "upload_unknown",
                    expected_uid=expected_uid,
                    cause=error,
                )
            raise
        return read_control_state(state_path, expected_uid=expected_uid)
    finally:
        client.token = ""
        token = ""


def association_is_active(association, certificate_id):
    return (
        association is not None
        and association["cert_id"] == certificate_id
        and association["enabled"] is True
        and association["status"] == "active"
    )


def poll_active_association(
    client,
    hostname,
    certificate_id,
    *,
    attempts=ASSOCIATION_POLL_ATTEMPTS,
    interval=ASSOCIATION_POLL_INTERVAL_SECONDS,
    sleeper=time.sleep,
):
    if not isinstance(attempts, int) or attempts < 1 or attempts > 20:
        raise AopError("invalid AOP association polling limit")
    for attempt in range(attempts):
        try:
            association = client.get_hostname_association(hostname)
        except AopError:
            association = None
        if association is not None and association["cert_id"] != certificate_id:
            raise AopError(
                "Cloudflare AOP hostname changed to a different certificate"
            )
        if association_is_active(association, certificate_id):
            return association
        if attempt + 1 < attempts:
            sleeper(interval)
    return None


@contextlib.contextmanager
def nginx_operation_lock(path=NGINX_OPERATION_LOCK, *, expected_uid=0):
    path = pathlib.Path(path)
    flags = os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise AopError("shared Nginx operation lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AopError("another Nginx apply operation is already in progress") from error
        yield
    except AopError:
        raise
    except OSError as error:
        raise AopError("shared Nginx operation lock is missing or unsafe") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def run_optional_readiness(hostname, ca_output, repo_dir):
    subprocess.run(
        [
            pathlib.Path(repo_dir) / "deploy" / "install-nginx-aop.sh",
            "check",
            "--stage",
            "probe",
            "--hostname",
            hostname,
            "--ca-file",
            pathlib.Path(ca_output),
        ],
        check=True,
        env=safe_subprocess_environment(),
    )


def _validate_resume_state(
    state, *, zone_id, hostname, ca_sha256, policy_sha256
):
    if state["zone_id"] != zone_id or state["hostname"] != hostname:
        raise AopError("AOP control state does not match the requested identity")
    if state["ca_sha256"] != ca_sha256:
        raise AopError("AOP control state does not match the installed CA")
    if state["policy_sha256"] != policy_sha256:
        raise AopError("AOP control state was created under a different policy")
    return state


def associate_aop(
    *,
    zone_id,
    hostname,
    ca_output,
    state_path,
    policy_sha256,
    token_provider,
    readiness_check,
    lock_path=NGINX_OPERATION_LOCK,
    opener=None,
    allow_test_paths=False,
    sleeper=time.sleep,
    poll_attempts=ASSOCIATION_POLL_ATTEMPTS,
):
    validate_zone_and_hostname(zone_id, hostname)
    if not SHA256_RE.fullmatch(policy_sha256 or ""):
        raise AopError("invalid AOP policy fingerprint")
    state_path = pathlib.Path(state_path)
    ca_output = pathlib.Path(ca_output)
    expected_uid = os.getuid() if allow_test_paths else 0
    if not allow_test_paths and (
        state_path != AOP_CONTROL_STATE
        or ca_output != AOP_CA_OUTPUT
        or pathlib.Path(lock_path) != NGINX_OPERATION_LOCK
    ):
        raise AopError("AOP associate paths must remain at their fixed origin locations")
    state = read_control_state(state_path, expected_uid=expected_uid)
    ca_fingerprint = read_public_ca_fingerprint(
        ca_output, expected_uid=expected_uid
    )
    _validate_resume_state(
        state,
        zone_id=zone_id,
        hostname=hostname,
        ca_sha256=ca_fingerprint,
        policy_sha256=policy_sha256,
    )
    if state["phase"] == "upload_in_flight":
        raise AopError("AOP upload did not reach a resumable state")

    with nginx_operation_lock(lock_path, expected_uid=expected_uid):
        state = read_control_state(state_path, expected_uid=expected_uid)
        ca_fingerprint = read_public_ca_fingerprint(
            ca_output, expected_uid=expected_uid
        )
        _validate_resume_state(
            state,
            zone_id=zone_id,
            hostname=hostname,
            ca_sha256=ca_fingerprint,
            policy_sha256=policy_sha256,
        )
        readiness_check(hostname, ca_output)
        token = token_provider()
        client = CloudflareAopClient(zone_id, token, opener=opener)
        try:
            certificate_id = state["certificate_id"]
            current = client.get_hostname_association(hostname)
            if current is not None and current["cert_id"] != certificate_id:
                raise AopError(
                    "a different AOP hostname association already exists"
                )
            if association_is_active(current, certificate_id):
                associated = _state_with_phase(state, "associated")
                try:
                    write_control_state(
                        state_path, associated, expected_uid=expected_uid
                    )
                except Exception as error:
                    _mark_unknown(
                        state_path,
                        state,
                        "associate_unknown",
                        expected_uid=expected_uid,
                        cause=AopError(
                            "active AOP association was not durably recorded"
                        ),
                    )
                return associated
            if state["phase"] == "associated":
                raise AopError(
                    "associated AOP control state no longer matches Cloudflare"
                )
            if state["phase"] == "upload_unknown" or certificate_id is None:
                raise AopError(
                    "unknown AOP upload must be reconciled before association"
                )

            in_flight = _state_with_phase(state, "associate_in_flight")
            write_control_state(state_path, in_flight, expected_uid=expected_uid)
            try:
                client.associate_hostname(hostname, certificate_id, True)
            except Exception:
                pass

            try:
                confirmed = poll_active_association(
                    client,
                    hostname,
                    certificate_id,
                    attempts=poll_attempts,
                    sleeper=sleeper,
                )
            except Exception as error:
                _mark_unknown(
                    state_path,
                    in_flight,
                    "associate_unknown",
                    expected_uid=expected_uid,
                    cause=AopError(
                        "AOP association could not be safely reconciled"
                    ),
                )
            if confirmed is None:
                _mark_unknown(
                    state_path,
                    in_flight,
                    "associate_unknown",
                    expected_uid=expected_uid,
                    cause=AopError(
                        "AOP association did not become active; safe retry state was retained"
                    ),
                )

            associated = _state_with_phase(in_flight, "associated")
            try:
                write_control_state(
                    state_path, associated, expected_uid=expected_uid
                )
            except Exception:
                _mark_unknown(
                    state_path,
                    in_flight,
                    "associate_unknown",
                    expected_uid=expected_uid,
                    cause=AopError(
                        "active AOP association was not durably recorded"
                    ),
                )
            return associated
        finally:
            client.token = ""
            token = ""


def parse_args(argv):
    argv = list(argv)
    mode = "check"
    if argv and argv[0] in {"check", "--apply"}:
        mode = argv.pop(0)
    parser = argparse.ArgumentParser(description="Configure per-hostname Cloudflare AOP")
    parser.add_argument("--stage", choices=("upload", "associate"))
    parser.add_argument("--zone-id", default="")
    parser.add_argument("--hostname", default="")
    parser.add_argument("--ca-output", default="")
    args = parser.parse_args(argv)
    args.mode = mode
    return args


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.mode != "--apply":
        if bool(args.zone_id) != bool(args.hostname):
            raise AopError("check mode requires both zone id and hostname when either is supplied")
        if args.zone_id:
            validate_zone_and_hostname(args.zone_id, args.hostname)
        if args.ca_output and pathlib.Path(args.ca_output) != AOP_CA_OUTPUT:
            raise AopError("AOP CA public certificate must remain at the fixed origin /etc path")
        print("AOP check only; no key was generated, no network request was made, and no file was changed")
        print("apply requires an explicit --stage upload or --stage associate")
        return 0

    if args.stage is None:
        raise AopError(
            "legacy one-step --apply is forbidden; select --stage upload or --stage associate"
        )
    sanitize_privileged_environment()
    repo_dir = pathlib.Path(__file__).resolve().parents[1]
    require_production_apply_context(
        repo_dir,
        streams=(sys.stdin, sys.stdout, sys.stderr),
    )
    if args.ca_output and pathlib.Path(args.ca_output) != AOP_CA_OUTPUT:
        raise AopError("AOP CA public certificate must remain at the fixed origin /etc path")
    validate_zone_and_hostname(args.zone_id, args.hostname)
    subprocess.run(
        [repo_dir / RELEASE_GUARD_RELATIVE_PATH, "check"],
        check=True,
        cwd=repo_dir,
        env=safe_subprocess_environment(),
    )
    require_ephemeral_secret_runtime()
    policy_sha256 = compute_policy_sha256(repo_dir)

    def token_provider():
        return getpass.getpass("One-time Cloudflare AOP API token: ")

    if args.stage == "upload":
        state = upload_aop(
            zone_id=args.zone_id,
            hostname=args.hostname,
            ca_output=args.ca_output,
            state_path=AOP_CONTROL_STATE,
            policy_sha256=policy_sha256,
            token_provider=token_provider,
        )
        print(
            "per-hostname AOP certificate uploaded but not associated; "
            f"install Nginx optional mode using {AOP_CA_OUTPUT}"
        )
    else:
        state = associate_aop(
            zone_id=args.zone_id,
            hostname=args.hostname,
            ca_output=AOP_CA_OUTPUT,
            state_path=AOP_CONTROL_STATE,
            policy_sha256=policy_sha256,
            token_provider=token_provider,
            readiness_check=lambda host, ca: run_optional_readiness(
                host, ca, repo_dir
            ),
        )
        print(
            "per-hostname AOP association is active; run the installer public "
            "probe before selecting required mode"
        )
    if state["phase"] not in {"uploaded", "associated"}:
        raise AopError("AOP stage did not reach its required durable state")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AopError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
