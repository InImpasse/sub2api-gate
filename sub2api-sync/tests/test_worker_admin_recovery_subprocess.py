import importlib.util
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "recover-worker-admin.py"
SPEC = importlib.util.spec_from_file_location("worker_admin_recovery_subprocess", SCRIPT)
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)

VERSION_ID = "11111111-1111-4111-8111-111111111111"
DEPLOYMENT_ID = "22222222-2222-4222-8222-222222222222"
REQUIRED_SECRETS = {
    "TURNSTILE_SECRET_KEY",
    "CLOUDFLARE_API_TOKEN",
    "ADMIN_PASSWORD_PBKDF2",
    "ADMIN_TOTP_SECRET",
    "CREDENTIAL_ENCRYPTION_KEY",
    "INVITE_ACCESS_HMAC_KEY",
    "SUB2API_SYNC_SECRET",
}


class WorkerAdminRecoverySubprocessTests(unittest.TestCase):
    def _prepare_stage(self, stage):
        worker = stage / "worker-allow-ip"
        worker.mkdir()
        config = worker / "wrangler.private.jsonc"
        config.write_text(json.dumps({"vars": {
            "ADMIN_USERNAME": "admin-test-user",
            "SUB2API_DEFAULT_BASE_URL": "https://api.example.test/v1",
        }}), encoding="ascii")
        config.chmod(0o600)
        (worker / "required-secrets.json").write_text(
            json.dumps({"version": 1, "required": sorted(REQUIRED_SECRETS)}) + "\n",
            encoding="ascii",
        )
        return worker

    def _write_fake_node(self, directory):
        fake = directory / "node"
        fake.write_text(
            "#!" + sys.executable + "\n"
            "import json, os, pathlib, stat, sys\n"
            f"VERSION_ID = {VERSION_ID!r}\n"
            f"DEPLOYMENT_ID = {DEPLOYMENT_ID!r}\n"
            f"REQUIRED = {sorted(REQUIRED_SECRETS)!r}\n"
            "args = sys.argv[1:]\n"
            "events = pathlib.Path(os.environ['FAKE_WRANGLER_EVENTS'])\n"
            "def event(name):\n"
            "    with events.open('a', encoding='ascii') as output: output.write(name + '\\n')\n"
            "if args and args[0].endswith('verify-worker-secret-list.mjs'):\n"
            "    event('verify-secrets'); sys.exit(0)\n"
            "if 'secret' in args and 'list' in args:\n"
            "    event('secret-list'); print(json.dumps([{'name': name, 'type': 'secret_text'} for name in REQUIRED])); sys.exit(0)\n"
            "if 'versions' in args and 'upload' in args:\n"
            "    secret = pathlib.Path(args[args.index('--secrets-file') + 1])\n"
            "    if stat.S_IMODE(secret.stat().st_mode) != 0o600: sys.exit(17)\n"
            "    if set(json.loads(secret.read_text(encoding='ascii'))) != {'ADMIN_PASSWORD_PBKDF2', 'ADMIN_TOTP_SECRET'}: sys.exit(18)\n"
            "    pathlib.Path(os.environ['WRANGLER_OUTPUT_FILE_PATH']).write_text(json.dumps({'type':'version-upload','version':1,'version_id':VERSION_ID}) + '\\n', encoding='ascii')\n"
            "    event('upload'); sys.exit(0)\n"
            "if 'versions' in args and 'view' in args:\n"
            "    event('version-view'); print(json.dumps({'id': VERSION_ID, 'annotations': {'workers/tag': os.environ['FAKE_WRANGLER_TAG'], 'workers/message': os.environ['FAKE_WRANGLER_MESSAGE']}, 'resources': {'bindings': [{'name': name, 'type': 'secret_text'} for name in REQUIRED]}})); sys.exit(0)\n"
            "if 'versions' in args and 'deploy' in args:\n"
            "    pathlib.Path(os.environ['WRANGLER_OUTPUT_FILE_PATH']).write_text(json.dumps({'type':'version-deploy','version':1,'deployment_id':DEPLOYMENT_ID}) + '\\n', encoding='ascii')\n"
            "    event('deploy'); sys.exit(0)\n"
            "if 'deployments' in args and 'status' in args:\n"
            "    event('deployment-status'); print(json.dumps({'id': DEPLOYMENT_ID, 'annotations': {'workers/message': os.environ['FAKE_WRANGLER_MESSAGE']}, 'versions': [{'version_id': VERSION_ID, 'percentage': 100}]})); sys.exit(0)\n"
            "sys.exit(19)\n",
            encoding="ascii",
        )
        fake.chmod(0o700)
        return fake

    def test_real_subprocess_boundary_uses_only_attested_fake_wrangler_protocol(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            stage = root / "stage"
            stage.mkdir()
            worker = self._prepare_stage(stage)
            events = root / "events"
            node = self._write_fake_node(root)
            environment = {
                "HOME": str(root),
                "FAKE_WRANGLER_EVENTS": str(events),
                "FAKE_WRANGLER_TAG": RECOVERY.RECOVERY_TAG,
                "FAKE_WRANGLER_MESSAGE": RECOVERY.RECOVERY_MESSAGE,
            }
            login_proofs = []

            result = RECOVERY.publish_recovery_version(
                stage,
                "local-test-password-with-sufficient-length",
                "JBSWY3DPEHPK3PXP",
                node,
                env=environment,
                login_prover=lambda config, _password, _seed: login_proofs.append(config),
            )

            self.assertEqual(result["version_id"], VERSION_ID)
            self.assertEqual(result["deployment_id"], DEPLOYMENT_ID)
            self.assertEqual(login_proofs, [worker / "wrangler.private.jsonc"])
            self.assertEqual(events.read_text(encoding="ascii").splitlines(), [
                "secret-list", "verify-secrets", "upload", "version-view",
                "deploy", "deployment-status", "secret-list", "verify-secrets",
            ])
            self.assertFalse(list(stage.glob(".admin-recovery-secrets-*.json")))
            self.assertFalse(list(stage.glob(".wrangler-*.json")))
