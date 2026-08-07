import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
GATE = ROOT / "deploy" / "verify-runtime-versions.sh"


class RuntimeVersionGateTests(unittest.TestCase):
    def test_check_mode_is_local_only(self):
        result = subprocess.run(
            ["bash", GATE, "check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no container was contacted", result.stdout)

    def test_running_mode_checks_binaries_not_image_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_docker = pathlib.Path(directory) / "docker"
            fake_docker.write_text(
                "#!/bin/sh\n"
                "case \"$2:$3\" in\n"
                "  sub2api:/app/sub2api) echo 'Sub2API 0.1.171 (commit: test)' ;;\n"
                "  sub2api-redis:redis-server) echo 'Redis server v=8.8.0 sha=0' ;;\n"
                "  sub2api-postgres:postgres) echo 'postgres (PostgreSQL) 18.1' ;;\n"
                "  *) exit 9 ;;\n"
                "esac\n"
            )
            fake_docker.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = f"{directory}:{env['PATH']}"
            result = subprocess.run(
                ["bash", GATE, "running"],
                cwd=ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("binaries verified", result.stdout)

    def test_running_mode_rejects_a_label_binary_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_docker = pathlib.Path(directory) / "docker"
            fake_docker.write_text(
                "#!/bin/sh\n"
                "case \"$2:$3\" in\n"
                "  sub2api:/app/sub2api) echo 'Sub2API 0.1.125' ;;\n"
                "  *) exit 9 ;;\n"
                "esac\n"
            )
            fake_docker.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = f"{directory}:{env['PATH']}"
            result = subprocess.run(
                ["bash", GATE, "running"],
                cwd=ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not 0.1.171", result.stderr)


if __name__ == "__main__":
    unittest.main()
