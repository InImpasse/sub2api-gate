import contextlib
import fcntl
import importlib.util
import json
import os
import pathlib
import ssl
import stat
import subprocess
import tempfile
import unittest
import urllib.error
from unittest import mock


ROOT = pathlib.Path(__file__).parents[2]
SCRIPT = ROOT / "deploy" / "configure-cloudflare-aop.py"
SPEC = importlib.util.spec_from_file_location("cloudflare_aop_tool", SCRIPT)
AOP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AOP)
ZONE_ID = "a" * 32
CERT_ID = "b" * 32
HOSTNAME = "api.example.test"


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return self.payload[:limit]


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if not self.responses:
            raise AssertionError("unexpected Cloudflare API request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return FakeResponse(response)


class FakeTTY:
    def __init__(self, is_tty=True):
        self._is_tty = is_tty

    def isatty(self):
        return self._is_tty


class CloudflareAopApiTests(unittest.TestCase):
    def test_api_token_is_canonical_and_bounded_before_any_request(self):
        for token in ("short", "t" * 513, "t" * 20 + "\r\nInjected: yes"):
            with self.subTest(length=len(token)), self.assertRaisesRegex(
                AOP.AopError, "invalid format"
            ):
                AOP.CloudflareAopClient(ZONE_ID, token, opener=FakeOpener([]))

    def test_upload_and_association_use_only_fixed_paths_and_authorization(self):
        opener = FakeOpener([
            {"success": True, "result": {"id": CERT_ID}},
            {"success": True, "result": [{
                "cert_id": CERT_ID,
                "hostname": HOSTNAME,
                "enabled": True,
            }]},
        ])
        client = AOP.CloudflareAopClient(ZONE_ID, "t" * 32, opener=opener)
        certificate_id = client.upload_certificate("PUBLIC CERT", "PRIVATE KEY")
        client.associate_hostname(HOSTNAME, certificate_id)

        upload, association = opener.requests
        self.assertEqual(upload[0].method, "POST")
        self.assertEqual(
            upload[0].full_url,
            f"{AOP.API_BASE}/zones/{ZONE_ID}/origin_tls_client_auth/hostnames/certificates",
        )
        self.assertEqual(association[0].method, "PUT")
        self.assertEqual(
            association[0].full_url,
            f"{AOP.API_BASE}/zones/{ZONE_ID}/origin_tls_client_auth/hostnames",
        )
        for request, timeout in opener.requests:
            self.assertEqual(timeout, 10)
            self.assertEqual(request.get_header("Authorization"), "Bearer " + "t" * 32)
        self.assertEqual(
            json.loads(association[0].data),
            {"config": [{
                "cert_id": CERT_ID,
                "enabled": True,
                "hostname": HOSTNAME,
            }]},
        )

    def test_hostname_lookup_uses_only_the_fixed_get_path_and_no_body(self):
        opener = FakeOpener([{
            "success": True,
            "result": {
                "cert_id": CERT_ID,
                "cert_status": "active",
                "enabled": True,
                "hostname": HOSTNAME,
            },
        }])
        client = AOP.CloudflareAopClient(ZONE_ID, "t" * 32, opener=opener)

        association = client.get_hostname_association(HOSTNAME)

        self.assertEqual(association["cert_id"], CERT_ID)
        request, timeout = opener.requests[0]
        self.assertEqual(request.method, "GET")
        self.assertIsNone(request.data)
        self.assertEqual(timeout, 10)
        self.assertEqual(
            request.full_url,
            f"{AOP.API_BASE}/zones/{ZONE_ID}/origin_tls_client_auth/hostnames/{HOSTNAME}",
        )

    def test_hostname_lookup_accepts_only_an_exact_404_as_absent(self):
        missing = urllib.error.HTTPError(
            "https://api.cloudflare.test", 404, "not found", {}, None
        )
        client = AOP.CloudflareAopClient(
            ZONE_ID, "t" * 32, opener=FakeOpener([missing])
        )
        self.assertIsNone(client.get_hostname_association(HOSTNAME))

        server_error = urllib.error.HTTPError(
            "https://api.cloudflare.test", 503, "unavailable", {}, None
        )
        client = AOP.CloudflareAopClient(
            ZONE_ID, "t" * 32, opener=FakeOpener([server_error])
        )
        with self.assertRaisesRegex(AOP.AopError, "API request failed"):
            client.get_hostname_association(HOSTNAME)

    def test_arbitrary_paths_are_rejected_before_credentials_are_attached(self):
        opener = FakeOpener([])
        client = AOP.CloudflareAopClient(ZONE_ID, "t" * 32, opener=opener)
        with self.assertRaisesRegex(AOP.AopError, "unexpected Cloudflare API method or path"):
            client.request("POST", "https://attacker.example/collect", {})
        with self.assertRaisesRegex(AOP.AopError, "unexpected Cloudflare API method or path"):
            client.request("GET", client.certificates_path, {})
        self.assertEqual(opener.requests, [])

    def test_certificate_delete_uses_no_request_body(self):
        opener = FakeOpener([{"success": True, "result": None}])
        client = AOP.CloudflareAopClient(ZONE_ID, "t" * 32, opener=opener)

        client.delete_certificate(CERT_ID)

        request, timeout = opener.requests[0]
        self.assertEqual(timeout, 10)
        self.assertEqual(request.method, "DELETE")
        self.assertIsNone(request.data)
        self.assertIsNone(request.get_header("Content-type"))
        with self.assertRaisesRegex(AOP.AopError, "must not include a body"):
            client.request("DELETE", f"{client.certificates_path}/{CERT_ID}", {})

    def test_hostname_association_rejects_non_boolean_states(self):
        client = AOP.CloudflareAopClient(
            ZONE_ID, "t" * 32, opener=FakeOpener([])
        )
        with self.assertRaisesRegex(AOP.AopError, "association state"):
            client.associate_hostname(HOSTNAME, CERT_ID, 1)

    def test_response_is_bounded_and_failure_body_is_not_exposed(self):
        opener = FakeOpener([b"x" * (AOP.MAX_API_RESPONSE_BYTES + 1)])
        client = AOP.CloudflareAopClient(ZONE_ID, "t" * 32, opener=opener)
        with self.assertRaisesRegex(AOP.AopError, "exceeded the byte limit") as raised:
            client.upload_certificate("PUBLIC", "PRIVATE")
        self.assertNotIn("x" * 100, str(raised.exception))

        private_body = "PRIVATE_RESPONSE_SENTINEL"
        opener = FakeOpener([{"success": False, "errors": [{"message": private_body}]}])
        client = AOP.CloudflareAopClient(ZONE_ID, "t" * 32, opener=opener)
        with self.assertRaisesRegex(AOP.AopError, "rejected the request") as raised:
            client.upload_certificate("PUBLIC", "PRIVATE")
        self.assertNotIn(private_body, str(raised.exception))

    def test_network_failure_is_generic(self):
        opener = FakeOpener([TimeoutError("PRIVATE_NETWORK_SENTINEL")])
        client = AOP.CloudflareAopClient(ZONE_ID, "t" * 32, opener=opener)
        with self.assertRaisesRegex(AOP.AopError, "result is unknown") as raised:
            client.upload_certificate("PUBLIC", "PRIVATE")
        self.assertNotIn("PRIVATE_NETWORK_SENTINEL", str(raised.exception))

    def test_default_transport_rejects_redirects_before_following_them(self):
        real_build_opener = AOP.urllib.request.build_opener
        captured_handlers = []

        def capture_build_opener(*handlers):
            captured_handlers.extend(handlers)
            return real_build_opener(*handlers)

        with mock.patch.dict(os.environ, {
            "HTTPS_PROXY": "http://attacker.example:8080",
            "https_proxy": "http://attacker.example:8081",
            "SSL_CERT_FILE": "/attacker/ca.pem",
            "SSL_CERT_DIR": "/attacker/certs",
            "PYTHONHTTPSVERIFY": "0",
        }), mock.patch.object(
            AOP.urllib.request, "build_opener", side_effect=capture_build_opener
        ):
            client = AOP.CloudflareAopClient(ZONE_ID, "t" * 32)
        proxy_handlers = [
            handler for handler in captured_handlers
            if isinstance(handler, AOP.urllib.request.ProxyHandler)
        ]
        self.assertEqual(len(proxy_handlers), 1)
        self.assertEqual(proxy_handlers[0].proxies, {})
        https_handlers = [
            handler for handler in client.opener.handlers
            if isinstance(handler, AOP.urllib.request.HTTPSHandler)
        ]
        self.assertEqual(len(https_handlers), 1)
        context = https_handlers[0]._context
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertGreater(context.cert_store_stats()["x509_ca"], 0)
        self.assertTrue(any(
            isinstance(handler, AOP.RejectRedirectHandler)
            for handler in client.opener.handlers
        ))
        handler = AOP.RejectRedirectHandler()
        request = AOP.urllib.request.Request(
            f"{AOP.API_BASE}/zones/{ZONE_ID}/origin_tls_client_auth/hostnames"
        )
        with self.assertRaisesRegex(AOP.AopError, "redirects are not allowed"):
            handler.redirect_request(
                request,
                None,
                307,
                "Temporary Redirect",
                {},
                "https://attacker.example/collect",
            )
        write_request = AOP.urllib.request.Request(
            f"{AOP.API_BASE}/zones/{ZONE_ID}/origin_tls_client_auth/hostnames",
            data=b"{}",
            method="PUT",
        )
        with self.assertRaisesRegex(
            AOP.AopRemoteResultUnknown, "redirects are not allowed"
        ):
            handler.redirect_request(
                write_request,
                None,
                307,
                "Temporary Redirect",
                {},
                "https://attacker.example/collect",
            )


class CloudflareAopCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with AOP.certificate_material(HOSTNAME) as material:
            cls.generated_material = {
                key: value
                for key, value in material.items()
                if key != "workspace"
            }

    def test_privileged_environment_and_subprocesses_ignore_inherited_injection(self):
        hostile_environment = {
            "PATH": "/attacker/bin",
            "HTTPS_PROXY": "http://attacker.example:8080",
            "https_proxy": "http://attacker.example:8081",
            "SSL_CERT_FILE": "/attacker/ca.pem",
            "SSL_CERT_DIR": "/attacker/certs",
            "PYTHONHTTPSVERIFY": "0",
            "OPENSSL_CONF": "/attacker/openssl.cnf",
            "OPENSSL_MODULES": "/attacker/modules",
            "LD_PRELOAD": "/attacker/library.so",
            "SSLKEYLOGFILE": "/attacker/tls.keys",
            "UNCHANGED": "kept",
        }
        AOP.sanitize_privileged_environment(hostile_environment)
        self.assertEqual(hostile_environment["PATH"], AOP.SAFE_COMMAND_PATH)
        self.assertEqual(hostile_environment["LANG"], "C")
        self.assertEqual(hostile_environment["LC_ALL"], "C")
        self.assertEqual(hostile_environment["UNCHANGED"], "kept")
        for name in AOP.DANGEROUS_ENVIRONMENT_NAMES:
            self.assertNotIn(name, {key.upper() for key in hostile_environment})

        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "tmpfs", ""))
        self.assertTrue(AOP.is_tmpfs(
            "/dev/shm", findmnt_binary="/safe/findmnt", runner=runner
        ))
        command = runner.call_args.args[0]
        kwargs = runner.call_args.kwargs
        self.assertEqual(command[0], pathlib.Path("/safe/findmnt"))
        self.assertEqual(kwargs["env"], AOP.safe_subprocess_environment())

        runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
        AOP.run_openssl(["version"], openssl_binary="/safe/openssl", runner=runner)
        command = runner.call_args.args[0]
        kwargs = runner.call_args.kwargs
        self.assertEqual(command[0], pathlib.Path("/safe/openssl"))
        self.assertEqual(kwargs["env"], AOP.safe_subprocess_environment())
        self.assertNotIn("OPENSSL_CONF", kwargs["env"])
        self.assertNotIn("OPENSSL_MODULES", kwargs["env"])

    def test_default_tool_paths_and_system_ca_are_fixed_absolute_paths(self):
        self.assertEqual(AOP.OPENSSL_BINARY, pathlib.Path("/usr/bin/openssl"))
        self.assertEqual(AOP.FINDMNT_BINARY, pathlib.Path("/usr/bin/findmnt"))
        self.assertEqual(
            AOP.SYSTEM_CA_BUNDLE,
            pathlib.Path("/etc/ssl/certs/ca-certificates.crt"),
        )
        for path in (AOP.OPENSSL_BINARY, AOP.FINDMNT_BINARY, AOP.SYSTEM_CA_BUNDLE):
            self.assertTrue(path.is_absolute())
            self.assertTrue(path.is_file())

    def test_system_ca_bundle_fails_closed_when_missing_or_not_regular(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            missing = parent / "missing.pem"
            with mock.patch.object(AOP, "SYSTEM_CA_BUNDLE", missing), self.assertRaisesRegex(
                AOP.AopError, "unavailable"
            ):
                AOP.build_system_tls_context()

            target = parent / "target.pem"
            target.write_text("not a certificate", encoding="ascii")
            link = parent / "linked.pem"
            link.symlink_to(target)
            with mock.patch.object(AOP, "SYSTEM_CA_BUNDLE", link), self.assertRaisesRegex(
                AOP.AopError, "trusted regular file"
            ):
                AOP.build_system_tls_context()

    def test_ephemeral_secret_runtime_disables_core_dumps_and_rejects_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            swaps = pathlib.Path(directory) / "swaps"
            swaps.write_text("Filename Type Size Used Priority\n", encoding="ascii")
            with mock.patch.object(AOP.resource, "setrlimit") as setrlimit, mock.patch.object(
                AOP.resource, "getrlimit", return_value=(0, 0)
            ):
                AOP.require_ephemeral_secret_runtime(swaps)
            setrlimit.assert_called_once_with(AOP.resource.RLIMIT_CORE, (0, 0))

            swaps.write_text(
                "Filename Type Size Used Priority\n/private/swap file 1024 0 -2\n",
                encoding="ascii",
            )
            with mock.patch.object(AOP.resource, "setrlimit"), mock.patch.object(
                AOP.resource, "getrlimit", return_value=(0, 0)
            ), self.assertRaisesRegex(AOP.AopError, "swap to be disabled"):
                AOP.require_ephemeral_secret_runtime(swaps)

            swaps.write_text("", encoding="ascii")
            with mock.patch.object(AOP.resource, "setrlimit"), mock.patch.object(
                AOP.resource, "getrlimit", return_value=(0, 0)
            ), self.assertRaisesRegex(AOP.AopError, "could not be verified"):
                AOP.require_ephemeral_secret_runtime(swaps)

    def test_ephemeral_secret_runtime_fails_when_core_limit_is_not_zero(self):
        with mock.patch.object(AOP.resource, "setrlimit"), mock.patch.object(
            AOP.resource, "getrlimit", return_value=(0, 1)
        ), self.assertRaisesRegex(AOP.AopError, "core-dump protection"):
            AOP.require_ephemeral_secret_runtime()

    def test_trusted_output_directory_rejects_wrong_owner_or_writable_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            parent.chmod(0o755)
            AOP.require_trusted_directory(parent, expected_uid=os.getuid())

            parent.chmod(0o775)
            with self.assertRaisesRegex(AOP.AopError, "must not be group or world writable"):
                AOP.require_trusted_directory(parent, expected_uid=os.getuid())

            parent.chmod(0o755)
            with self.assertRaisesRegex(AOP.AopError, "trusted owner"):
                AOP.require_trusted_directory(parent, expected_uid=os.getuid() + 1)

    def test_ca_output_fsyncs_the_parent_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            parent.chmod(0o700)
            output = parent / "client-ca.pem"
            fsync_targets = []
            real_fsync = os.fsync

            def record_fsync(descriptor):
                fsync_targets.append(stat.S_ISDIR(os.fstat(descriptor).st_mode))
                return real_fsync(descriptor)

            with mock.patch.object(AOP.os, "fsync", side_effect=record_fsync):
                AOP.write_ca_public_key(
                    output,
                    "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
                )

            self.assertTrue(output.is_file())
            self.assertIn(True, fsync_targets)

    def test_certificate_keys_live_in_tmpfs_and_are_deleted_after_use(self):
        with AOP.certificate_material(HOSTNAME) as material:
            workspace = material["workspace"]
            self.assertTrue(workspace.is_dir())
            self.assertIn("BEGIN CERTIFICATE", material["ca_certificate"])
            self.assertEqual(material["ca_certificate"].count("BEGIN CERTIFICATE"), 1)
            self.assertEqual(material["ca_certificate"].count("END CERTIFICATE"), 1)
            self.assertIn("BEGIN CERTIFICATE", material["client_certificate"])
            self.assertIn("PRIVATE KEY", material["client_private_key"])
            verification = subprocess.run(
                [
                    AOP.OPENSSL_BINARY, "verify",
                    "-CAfile", workspace / "ca.pem",
                    workspace / "client.pem",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(verification.returncode, 0, verification.stderr)
            details = subprocess.run(
                [AOP.OPENSSL_BINARY, "x509", "-in", workspace / "client.pem", "-noout", "-text"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertIn("TLS Web Client Authentication", details)
            self.assertIn(f"DNS:{HOSTNAME}", details)
        self.assertFalse(workspace.exists())

    def test_tmpfs_cleanup_failure_is_reported_and_never_treated_as_success(self):
        workspace = None
        try:
            with mock.patch.object(
                AOP.shutil, "rmtree", side_effect=OSError("PRIVATE_CLEANUP_SENTINEL")
            ):
                with self.assertRaisesRegex(
                    AOP.AopError, "private-key cleanup failed"
                ) as raised:
                    with AOP.certificate_material(HOSTNAME) as material:
                        workspace = material["workspace"]
            self.assertNotIn("PRIVATE_CLEANUP_SENTINEL", str(raised.exception))
        finally:
            if workspace is not None:
                AOP.shutil.rmtree(workspace, ignore_errors=True)

    def test_ca_output_rejects_certificate_chains_and_trailing_content(self):
        certificate = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "client-ca.pem"
            with self.assertRaisesRegex(AOP.AopError, "exactly one PEM certificate"):
                AOP.write_ca_public_key(output, certificate + certificate)
            with self.assertRaisesRegex(AOP.AopError, "exactly one PEM certificate"):
                AOP.write_ca_public_key(output, certificate + "TRAILING\n")
            self.assertFalse(output.exists())

    def test_default_check_is_offline_and_validates_optional_identity(self):
        self.assertEqual(AOP.main([]), 0)
        self.assertEqual(
            AOP.main(["check", "--zone-id", ZONE_ID, "--hostname", HOSTNAME]),
            0,
        )
        with self.assertRaisesRegex(AOP.AopError, "requires both"):
            AOP.main(["check", "--zone-id", ZONE_ID])
        with self.assertRaisesRegex(AOP.AopError, "fixed origin /etc path"):
            AOP.main(["check", "--ca-output", "/mnt/data/sub2api-gate/aop/ca.pem"])

    def test_apply_contract_requires_tty_and_clean_worktree_guard(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertTrue(source.startswith("#!/usr/bin/python3 -I\n"))
        self.assertTrue(SCRIPT.stat().st_mode & stat.S_IXUSR)
        self.assertLess(
            source.index(
                'if __name__ == "__main__" and sys.argv[1:2] == ["--apply"]:'
            ),
            source.index("import ssl"),
        )
        self.assertIn("TRUSTED_RELEASE_ROOT = pathlib.Path", source)
        self.assertIn(
            "stdin.isatty() and stdout.isatty() and stderr.isatty()", source
        )
        self.assertIn("require_production_apply_context(", source)
        self.assertIn("sanitize_privileged_environment()", source)
        self.assertLess(
            source.index("sanitize_privileged_environment()", source.index("def main")),
            source.index('getpass.getpass("One-time Cloudflare AOP API token: ")'),
        )
        self.assertIn("RELEASE_GUARD_RELATIVE_PATH", source)
        self.assertLess(
            source.index("require_ephemeral_secret_runtime()"),
            source.index('getpass.getpass("One-time Cloudflare AOP API token: ")'),
        )
        self.assertNotIn("CLOUDFLARE_API_TOKEN", source)
        self.assertEqual(AOP.API_BASE, "https://api.cloudflare.com/client/v4")

    def test_apply_context_requires_canonical_sources_and_all_private_ttys(self):
        with tempfile.TemporaryDirectory() as directory:
            trusted_root = pathlib.Path(directory) / "sub2api-gate-release"
            source = trusted_root / "deploy" / "configure-cloudflare-aop.py"
            release_guard = trusted_root / "deploy" / "require-clean-worktree.sh"
            installer = trusted_root / "deploy" / "install-nginx-aop.sh"
            optional_snippet = (
                trusted_root / "nginx" / "snippets" / "sub2api-aop-optional.conf"
            )
            for path in (
                trusted_root,
                trusted_root / "deploy",
                trusted_root / "nginx",
                trusted_root / "nginx" / "snippets",
            ):
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(0o755)
            for path in (source, release_guard, installer):
                path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
                path.chmod(0o755)
            optional_snippet.write_text("ssl_verify_client optional;\n", encoding="ascii")
            optional_snippet.chmod(0o644)

            with mock.patch.object(AOP, "TRUSTED_RELEASE_ROOT", trusted_root):
                AOP.require_trusted_release_tree(
                    trusted_root,
                    source_path=source,
                    expected_uid=os.getuid(),
                )
                outside_source = trusted_root / "deploy" / "other.py"
                outside_source.write_text("pass\n", encoding="ascii")
                outside_source.chmod(0o644)
                with self.assertRaisesRegex(
                    AOP.AopError, "outside the trusted release tree"
                ):
                    AOP.require_trusted_release_tree(
                        trusted_root,
                        source_path=outside_source,
                        expected_uid=os.getuid(),
                    )

        with mock.patch.object(AOP, "TRUSTED_RELEASE_ROOT", ROOT), \
             mock.patch.object(AOP.os, "geteuid", return_value=0), \
             mock.patch.object(AOP, "require_trusted_release_tree") as trusted_tree:
            with self.assertRaisesRegex(AOP.AopError, "private interactive TTY"):
                AOP.require_production_apply_context(
                    ROOT,
                    streams=(FakeTTY(), FakeTTY(False), FakeTTY()),
                )
            trusted_tree.assert_not_called()

            AOP.require_production_apply_context(
                ROOT,
                streams=(FakeTTY(), FakeTTY(), FakeTTY()),
            )
            trusted_tree.assert_called_once_with(ROOT)

        original_environment = os.environ.copy()
        with mock.patch.dict(os.environ, original_environment, clear=True), \
             mock.patch.object(AOP.os, "geteuid", return_value=0), \
             mock.patch.object(AOP.sys, "stdin", FakeTTY()), \
             mock.patch.object(AOP.sys, "stdout", FakeTTY()), \
             mock.patch.object(AOP.sys, "stderr", FakeTTY()), \
             mock.patch.object(AOP.getpass, "getpass") as token_reader, \
             mock.patch.object(AOP.subprocess, "run") as runner:
            with self.assertRaisesRegex(
                AOP.AopError, "trusted production release tree"
            ):
                AOP.main([
                    "--apply",
                    "--stage",
                    "upload",
                    "--zone-id",
                    ZONE_ID,
                    "--hostname",
                    HOSTNAME,
                ])
            self.assertEqual(os.environ["PATH"], AOP.SAFE_COMMAND_PATH)
        self.assertEqual(dict(os.environ), original_environment)
        token_reader.assert_not_called()
        runner.assert_not_called()

    def test_legacy_one_step_apply_is_rejected_before_token_or_network(self):
        with mock.patch.object(AOP.getpass, "getpass") as getpass_mock:
            with self.assertRaisesRegex(AOP.AopError, "one-step --apply is forbidden"):
                AOP.main([
                    "--apply",
                    "--zone-id",
                    ZONE_ID,
                    "--hostname",
                    HOSTNAME,
                ])
        getpass_mock.assert_not_called()

    def test_optional_readiness_uses_installer_probe_check_with_same_ca(self):
        with mock.patch.object(AOP.subprocess, "run") as run:
            AOP.run_optional_readiness(HOSTNAME, AOP.AOP_CA_OUTPUT, ROOT)
        command = run.call_args.args[0]
        self.assertEqual(
            command,
            [
                ROOT / "deploy" / "install-nginx-aop.sh",
                "check",
                "--stage",
                "probe",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                AOP.AOP_CA_OUTPUT,
            ],
        )
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertEqual(
            run.call_args.kwargs["env"], AOP.safe_subprocess_environment()
        )


class CloudflareAopStagedWorkflowTests(unittest.TestCase):
    POLICY_SHA256 = "c" * 64

    @classmethod
    def setUpClass(cls):
        with AOP.certificate_material(HOSTNAME) as material:
            cls.material = {
                key: value
                for key, value in material.items()
                if key != "workspace"
            }

    @contextlib.contextmanager
    def fake_material(self, _hostname):
        yield dict(self.material)

    @staticmethod
    def not_found():
        return urllib.error.HTTPError(
            "https://api.cloudflare.test", 404, "not found", {}, None
        )

    @staticmethod
    def association(certificate_id=CERT_ID, *, enabled=True, status="active"):
        return {
            "success": True,
            "result": {
                "cert_id": certificate_id,
                "cert_status": status,
                "enabled": enabled,
                "hostname": HOSTNAME,
            },
        }

    def make_paths(self, directory):
        parent = pathlib.Path(directory)
        parent.chmod(0o700)
        ca_output = parent / "client-ca.pem"
        state_path = parent / "cloudflare-control-state.json"
        lock_path = parent / "nginx-operation.lock"
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
        return ca_output, state_path, lock_path

    def write_uploaded_state(self, ca_output, state_path):
        AOP.write_ca_public_key(ca_output, self.material["ca_certificate"])
        state = AOP.make_control_state(
            phase="uploaded",
            zone_id=ZONE_ID,
            hostname=HOSTNAME,
            certificate_id=CERT_ID,
            ca_sha256=AOP.certificate_sha256(self.material["ca_certificate"]),
            policy_sha256=self.POLICY_SHA256,
        )
        AOP.write_control_state(
            state_path, state, expected_uid=os.getuid()
        )
        return state

    def run_upload(self, opener, ca_output, state_path):
        with mock.patch.object(
            AOP, "certificate_material", side_effect=self.fake_material
        ):
            return AOP.upload_aop(
                zone_id=ZONE_ID,
                hostname=HOSTNAME,
                ca_output=ca_output,
                state_path=state_path,
                policy_sha256=self.POLICY_SHA256,
                token_provider=lambda: "t" * 32,
                opener=opener,
                allow_test_output=True,
            )

    def test_upload_is_unassociated_and_persists_only_public_recovery_state(self):
        opener = FakeOpener([
            self.not_found(),
            {"success": True, "result": {"id": CERT_ID}},
        ])
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, _ = self.make_paths(directory)

            state = self.run_upload(opener, ca_output, state_path)

            self.assertEqual(state["phase"], "uploaded")
            self.assertEqual(state["certificate_id"], CERT_ID)
            self.assertEqual(set(state), AOP.CONTROL_STATE_FIELDS)
            state_text = state_path.read_text(encoding="ascii")
            self.assertNotIn("t" * 20, state_text)
            self.assertNotIn("PRIVATE KEY", state_text)
            self.assertNotIn("PRIVATE KEY", ca_output.read_text(encoding="ascii"))
            self.assertEqual(state_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual([request.method for request, _ in opener.requests], ["GET", "POST"])

    def test_upload_refuses_any_existing_hostname_association_before_post(self):
        opener = FakeOpener([self.association("d" * 32, enabled=False)])
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, _ = self.make_paths(directory)
            with mock.patch.object(AOP, "certificate_material") as material:
                with self.assertRaisesRegex(AOP.AopError, "already exists"):
                    self.run_upload(opener, ca_output, state_path)
            material.assert_not_called()
            self.assertFalse(ca_output.exists())
            self.assertFalse(state_path.exists())
            self.assertEqual([request.method for request, _ in opener.requests], ["GET"])

    def test_losing_ca_creation_race_never_deletes_the_winner_artifact(self):
        opener = FakeOpener([self.not_found()])
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, _ = self.make_paths(directory)
            ca_output.write_text("WINNER_PUBLIC_CA\n", encoding="ascii")
            ca_output.chmod(0o600)
            with mock.patch.object(
                AOP, "prepare_ca_output", return_value=ca_output
            ), self.assertRaisesRegex(AOP.AopError, "refusing to overwrite"):
                self.run_upload(opener, ca_output, state_path)
            self.assertEqual(
                ca_output.read_text(encoding="ascii"), "WINNER_PUBLIC_CA\n"
            )
            self.assertFalse(state_path.exists())
            self.assertEqual(
                [request.method for request, _ in opener.requests], ["GET"]
            )

    def test_ambiguous_upload_retains_ca_and_marks_unknown_without_delete(self):
        for response in (
            TimeoutError("PRIVATE_TIMEOUT"),
            urllib.error.HTTPError(
                "https://api.cloudflare.test", 503, "unavailable", {}, None
            ),
            {"success": True},
            b"not-json",
        ):
            with self.subTest(response=type(response).__name__), tempfile.TemporaryDirectory() as directory:
                opener = FakeOpener([self.not_found(), response])
                ca_output, state_path, _ = self.make_paths(directory)
                with self.assertRaises(AOP.AopRemoteResultUnknown):
                    self.run_upload(opener, ca_output, state_path)
                state = AOP.read_control_state(
                    state_path, expected_uid=os.getuid()
                )
                self.assertEqual(state["phase"], "upload_unknown")
                self.assertTrue(ca_output.exists())
                self.assertNotIn(
                    "DELETE", [request.method for request, _ in opener.requests]
                )

    def test_definitive_upload_rejection_removes_local_ca_and_state(self):
        opener = FakeOpener([
            self.not_found(),
            {"success": False, "errors": [{"message": "PRIVATE_FAILURE"}]},
        ])
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, _ = self.make_paths(directory)
            with self.assertRaisesRegex(AOP.AopError, "rejected the request") as raised:
                self.run_upload(opener, ca_output, state_path)
            self.assertNotIn("PRIVATE_FAILURE", str(raised.exception))
            self.assertFalse(ca_output.exists())
            self.assertFalse(state_path.exists())
            self.assertNotIn(
                "DELETE", [request.method for request, _ in opener.requests]
            )

    def test_post_upload_state_fsync_failure_is_marked_unknown(self):
        opener = FakeOpener([
            self.not_found(),
            {"success": True, "result": {"id": CERT_ID}},
        ])
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, _ = self.make_paths(directory)
            with mock.patch.object(
                AOP,
                "_fsync_directory",
                side_effect=[None, OSError("PRIVATE_FSYNC_FAILURE"), None],
            ):
                with self.assertRaisesRegex(
                    AOP.AopError, "not durably recorded"
                ) as raised:
                    self.run_upload(opener, ca_output, state_path)
            self.assertNotIn("PRIVATE_FSYNC_FAILURE", str(raised.exception))
            state = AOP.read_control_state(
                state_path, expected_uid=os.getuid()
            )
            self.assertEqual(state["phase"], "upload_unknown")
            self.assertEqual(state["certificate_id"], CERT_ID)
            self.assertTrue(ca_output.exists())
            self.assertEqual(
                [request.method for request, _ in opener.requests], ["GET", "POST"]
            )

    def test_private_material_cleanup_failure_keeps_recovery_state(self):
        @contextlib.contextmanager
        def failing_cleanup(_hostname):
            yield dict(self.material)
            raise AOP.AopError("AOP tmpfs private-key cleanup failed")

        opener = FakeOpener([
            self.not_found(),
            {"success": True, "result": {"id": CERT_ID}},
        ])
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, _ = self.make_paths(directory)
            with mock.patch.object(
                AOP, "certificate_material", side_effect=failing_cleanup
            ):
                with self.assertRaisesRegex(
                    AOP.AopError, "private-key cleanup failed"
                ):
                    AOP.upload_aop(
                        zone_id=ZONE_ID,
                        hostname=HOSTNAME,
                        ca_output=ca_output,
                        state_path=state_path,
                        policy_sha256=self.POLICY_SHA256,
                        token_provider=lambda: "t" * 32,
                        opener=opener,
                        allow_test_output=True,
                    )
            state = AOP.read_control_state(
                state_path, expected_uid=os.getuid()
            )
            self.assertEqual(state["phase"], "upload_unknown")
            self.assertEqual(state["certificate_id"], CERT_ID)
            self.assertTrue(ca_output.exists())
            self.assertNotIn(
                "DELETE", [request.method for request, _ in opener.requests]
            )

    def test_control_state_rejects_symlinks_wide_permissions_and_schema_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, _ = self.make_paths(directory)
            self.write_uploaded_state(ca_output, state_path)
            state_path.chmod(0o644)
            with self.assertRaisesRegex(AOP.AopError, "unsafe ownership or permissions"):
                AOP.read_control_state(state_path, expected_uid=os.getuid())

            state_path.unlink()
            target = pathlib.Path(directory) / "target-state"
            target.write_text("{}", encoding="ascii")
            target.chmod(0o600)
            state_path.symlink_to(target)
            with self.assertRaisesRegex(AOP.AopError, "missing or unsafe"):
                AOP.read_control_state(state_path, expected_uid=os.getuid())

            state_path.unlink()
            invalid = AOP.make_control_state(
                phase="uploaded",
                zone_id=ZONE_ID,
                hostname=HOSTNAME,
                certificate_id=CERT_ID,
                ca_sha256="e" * 64,
                policy_sha256=self.POLICY_SHA256,
            )
            invalid["unexpected"] = "field"
            state_path.write_text(json.dumps(invalid), encoding="ascii")
            state_path.chmod(0o600)
            with self.assertRaisesRegex(AOP.AopError, "invalid schema"):
                AOP.read_control_state(state_path, expected_uid=os.getuid())

    def test_control_state_rejects_hardlinks_oversize_and_duplicate_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, _ = self.make_paths(directory)
            self.write_uploaded_state(ca_output, state_path)
            hardlink = pathlib.Path(directory) / "state-copy"
            os.link(state_path, hardlink)
            with self.assertRaisesRegex(AOP.AopError, "unsafe ownership or permissions"):
                AOP.read_control_state(state_path, expected_uid=os.getuid())

            hardlink.unlink()
            state_path.write_bytes(b"{" + b"x" * AOP.MAX_CONTROL_STATE_BYTES + b"}")
            state_path.chmod(0o600)
            with self.assertRaisesRegex(AOP.AopError, "unsafe ownership or permissions"):
                AOP.read_control_state(state_path, expected_uid=os.getuid())

            state_path.write_text(
                '{"version":1,"version":1}', encoding="ascii"
            )
            state_path.chmod(0o600)
            with self.assertRaisesRegex(AOP.AopError, "duplicate fields"):
                AOP.read_control_state(state_path, expected_uid=os.getuid())

    def test_upload_guard_refuses_installed_or_active_nginx_aop_state(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            install_state = parent / "install-state"
            active = parent / "active.conf"
            with mock.patch.object(
                AOP, "NGINX_INSTALL_STATE", install_state
            ), mock.patch.object(AOP, "NGINX_ACTIVE_SNIPPET", active):
                install_state.write_text("stage=required\n", encoding="ascii")
                with self.assertRaisesRegex(AOP.AopError, "must be retired"):
                    AOP.require_no_installed_aop_conflict(expected_uid=os.getuid())
                install_state.unlink()
                active.write_text(
                    "ssl_client_certificate /old/ca.pem;\n"
                    "ssl_verify_client on;\n",
                    encoding="ascii",
                )
                active.chmod(0o644)
                with self.assertRaisesRegex(AOP.AopError, "must not be overwritten"):
                    AOP.require_no_installed_aop_conflict(expected_uid=os.getuid())

    def test_associate_holds_shared_lock_and_requires_optional_before_token(self):
        opener = FakeOpener([
            self.not_found(),
            {"success": True, "result": [{
                "cert_id": CERT_ID,
                "enabled": True,
                "hostname": HOSTNAME,
            }]},
            self.association(status="pending_deployment"),
            self.association(),
        ])
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, lock_path = self.make_paths(directory)
            self.write_uploaded_state(ca_output, state_path)
            events = []

            def readiness(hostname, ca_path):
                events.append("readiness")
                self.assertEqual(hostname, HOSTNAME)
                self.assertEqual(ca_path, ca_output)
                descriptor = os.open(lock_path, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(descriptor)

            def token_provider():
                events.append("token")
                return "t" * 32

            state = AOP.associate_aop(
                zone_id=ZONE_ID,
                hostname=HOSTNAME,
                ca_output=ca_output,
                state_path=state_path,
                policy_sha256=self.POLICY_SHA256,
                token_provider=token_provider,
                readiness_check=readiness,
                lock_path=lock_path,
                opener=opener,
                allow_test_paths=True,
                sleeper=lambda _seconds: None,
            )
            self.assertEqual(events, ["readiness", "token"])
            self.assertEqual(state["phase"], "associated")
            self.assertEqual(
                [request.method for request, _ in opener.requests],
                ["GET", "PUT", "GET", "GET"],
            )

    def test_ambiguous_put_is_reconciled_by_get_without_reverse_write(self):
        opener = FakeOpener([
            self.not_found(),
            TimeoutError("PRIVATE_TIMEOUT"),
            self.association(),
        ])
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, lock_path = self.make_paths(directory)
            self.write_uploaded_state(ca_output, state_path)
            state = AOP.associate_aop(
                zone_id=ZONE_ID,
                hostname=HOSTNAME,
                ca_output=ca_output,
                state_path=state_path,
                policy_sha256=self.POLICY_SHA256,
                token_provider=lambda: "t" * 32,
                readiness_check=lambda _host, _ca: None,
                lock_path=lock_path,
                opener=opener,
                allow_test_paths=True,
                sleeper=lambda _seconds: None,
            )
            self.assertEqual(state["phase"], "associated")
            self.assertEqual(
                [request.method for request, _ in opener.requests],
                ["GET", "PUT", "GET"],
            )

    def test_unconfirmed_association_retains_unknown_state_and_never_reverses(self):
        opener = FakeOpener([
            self.not_found(),
            TimeoutError("PRIVATE_TIMEOUT"),
            self.not_found(),
            self.not_found(),
        ])
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, lock_path = self.make_paths(directory)
            self.write_uploaded_state(ca_output, state_path)
            with self.assertRaisesRegex(AOP.AopError, "safe retry state"):
                AOP.associate_aop(
                    zone_id=ZONE_ID,
                    hostname=HOSTNAME,
                    ca_output=ca_output,
                    state_path=state_path,
                    policy_sha256=self.POLICY_SHA256,
                    token_provider=lambda: "t" * 32,
                    readiness_check=lambda _host, _ca: None,
                    lock_path=lock_path,
                    opener=opener,
                    allow_test_paths=True,
                    sleeper=lambda _seconds: None,
                    poll_attempts=2,
                )
            state = AOP.read_control_state(
                state_path, expected_uid=os.getuid()
            )
            self.assertEqual(state["phase"], "associate_unknown")
            self.assertTrue(ca_output.exists())
            methods = [request.method for request, _ in opener.requests]
            self.assertEqual(methods, ["GET", "PUT", "GET", "GET"])
            self.assertNotIn("DELETE", methods)

    def test_post_association_state_fsync_failure_is_marked_unknown(self):
        opener = FakeOpener([
            self.not_found(),
            {"success": True, "result": [{
                "cert_id": CERT_ID,
                "enabled": True,
                "hostname": HOSTNAME,
            }]},
            self.association(),
        ])
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, lock_path = self.make_paths(directory)
            self.write_uploaded_state(ca_output, state_path)
            with mock.patch.object(
                AOP,
                "_fsync_directory",
                side_effect=[None, OSError("PRIVATE_FSYNC_FAILURE"), None],
            ):
                with self.assertRaisesRegex(
                    AOP.AopError, "not durably recorded"
                ) as raised:
                    AOP.associate_aop(
                        zone_id=ZONE_ID,
                        hostname=HOSTNAME,
                        ca_output=ca_output,
                        state_path=state_path,
                        policy_sha256=self.POLICY_SHA256,
                        token_provider=lambda: "t" * 32,
                        readiness_check=lambda _host, _ca: None,
                        lock_path=lock_path,
                        opener=opener,
                        allow_test_paths=True,
                        sleeper=lambda _seconds: None,
                    )
            self.assertNotIn("PRIVATE_FSYNC_FAILURE", str(raised.exception))
            state = AOP.read_control_state(
                state_path, expected_uid=os.getuid()
            )
            self.assertEqual(state["phase"], "associate_unknown")
            self.assertTrue(ca_output.exists())
            self.assertEqual(
                [request.method for request, _ in opener.requests],
                ["GET", "PUT", "GET"],
            )

    def test_associate_rejects_optional_failure_and_state_mismatch_before_token(self):
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, lock_path = self.make_paths(directory)
            self.write_uploaded_state(ca_output, state_path)
            token_provider = mock.Mock(return_value="t" * 32)
            opener = FakeOpener([])
            with self.assertRaisesRegex(AOP.AopError, "OPTIONAL_NOT_READY"):
                AOP.associate_aop(
                    zone_id=ZONE_ID,
                    hostname=HOSTNAME,
                    ca_output=ca_output,
                    state_path=state_path,
                    policy_sha256=self.POLICY_SHA256,
                    token_provider=token_provider,
                    readiness_check=lambda _host, _ca: (_ for _ in ()).throw(
                        AOP.AopError("OPTIONAL_NOT_READY")
                    ),
                    lock_path=lock_path,
                    opener=opener,
                    allow_test_paths=True,
                )
            token_provider.assert_not_called()
            self.assertEqual(opener.requests, [])

            with self.assertRaisesRegex(AOP.AopError, "different policy"):
                AOP.associate_aop(
                    zone_id=ZONE_ID,
                    hostname=HOSTNAME,
                    ca_output=ca_output,
                    state_path=state_path,
                    policy_sha256="f" * 64,
                    token_provider=token_provider,
                    readiness_check=lambda _host, _ca: None,
                    lock_path=lock_path,
                    opener=opener,
                    allow_test_paths=True,
                )
            token_provider.assert_not_called()

            replacement_ca = pathlib.Path(directory) / "replacement-ca.pem"
            with AOP.certificate_material("other.example.test") as replacement:
                AOP.write_ca_public_key(
                    replacement_ca, replacement["ca_certificate"]
                )
            ca_output.unlink()
            replacement_ca.replace(ca_output)
            with self.assertRaisesRegex(AOP.AopError, "does not match the installed CA"):
                AOP.associate_aop(
                    zone_id=ZONE_ID,
                    hostname=HOSTNAME,
                    ca_output=ca_output,
                    state_path=state_path,
                    policy_sha256=self.POLICY_SHA256,
                    token_provider=token_provider,
                    readiness_check=lambda _host, _ca: None,
                    lock_path=lock_path,
                    opener=opener,
                    allow_test_paths=True,
                )
            token_provider.assert_not_called()

    def test_associate_refuses_a_different_remote_certificate_before_put(self):
        opener = FakeOpener([self.association("d" * 32)])
        with tempfile.TemporaryDirectory() as directory:
            ca_output, state_path, lock_path = self.make_paths(directory)
            self.write_uploaded_state(ca_output, state_path)
            with self.assertRaisesRegex(AOP.AopError, "different AOP"):
                AOP.associate_aop(
                    zone_id=ZONE_ID,
                    hostname=HOSTNAME,
                    ca_output=ca_output,
                    state_path=state_path,
                    policy_sha256=self.POLICY_SHA256,
                    token_provider=lambda: "t" * 32,
                    readiness_check=lambda _host, _ca: None,
                    lock_path=lock_path,
                    opener=opener,
                    allow_test_paths=True,
                )
            self.assertEqual(
                [request.method for request, _ in opener.requests], ["GET"]
            )
            state = AOP.read_control_state(
                state_path, expected_uid=os.getuid()
            )
            self.assertEqual(state["phase"], "uploaded")


if __name__ == "__main__":
    unittest.main()
