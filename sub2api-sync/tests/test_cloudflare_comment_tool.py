import json
import os
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "migrate-cloudflare-comments.mjs"


class CloudflareCommentToolTests(unittest.TestCase):
    def test_default_check_is_offline_and_needs_no_credentials(self):
        environment = os.environ.copy()
        for name in (
            "CLOUDFLARE_ACCOUNT_ID",
            "CLOUDFLARE_IP_LIST_ID",
            "CLOUDFLARE_API_TOKEN",
            "INVITE_ACCESS_HMAC_KEY",
        ):
            environment.pop(name, None)

        result = subprocess.run(
            ["node", str(SCRIPT), "check"],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {"mode": "check", "syntheticItems": 3},
        )
        self.assertEqual(result.stderr, "")

    def test_apply_reads_hmac_only_from_the_private_state_file(self):
        source = SCRIPT.read_text()
        self.assertNotIn("process.env.INVITE_ACCESS_HMAC_KEY", source)
        self.assertNotIn("process.argv", source.split("const hmacKey", 1)[-1] if "const hmacKey" in source else "")
        self.assertIn("readPrivateHmacState", source)
        self.assertIn("destroyPrivateHmacState", source)
        self.assertIn("stateDestroyed: true", source)
        self.assertGreater(
            source.rindex("destroyPrivateHmacState(statePath, state"),
            source.index("assertCloudflareReplacement(replacement.items, verified.items)"),
        )


if __name__ == "__main__":
    unittest.main()
