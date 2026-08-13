import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
CLEANUP = ROOT / "deploy" / "cleanup-conversation-logs.sh"
LEGACY_NAME = "legacy-sub2api"
CONTAINER_ID = "a" * 64


class CleanupSafetyTests(unittest.TestCase):
    def environment(self, root, data_dir, nginx_dir):
        fake_docker = root / "fake-docker"
        fake_docker.write_text(textwrap.dedent(f"""
            #!/usr/bin/env python3
            import os
            import pathlib
            import sys

            args = sys.argv[1:]
            if args[:1] == ["--host"]:
                args = args[2:]
            root = pathlib.Path(os.environ["FAKE_DOCKER_ROOT"])
            present = pathlib.Path(os.environ["FAKE_CONTAINER_PRESENT"])
            running = os.environ.get("FAKE_CONTAINER_RUNNING", "false")
            name = {LEGACY_NAME!r}
            container_id = {CONTAINER_ID!r}
            log_path = root / "containers" / container_id / (container_id + "-json.log")
            if args[:2] == ["info", "--format"]:
                if args[2] == "{{{{.DockerRootDir}}}}":
                    print(root)
                elif args[2] == "{{{{.ID}}}}":
                    print("test-daemon-id")
                else:
                    raise SystemExit(2)
                raise SystemExit(0)
            if args[:2] != ["container", "inspect"]:
                raise SystemExit(2)
            if "--format" in args:
                if not present.exists():
                    raise SystemExit(1)
                template = args[args.index("--format") + 1]
                target = args[-1]
                if target not in (name, container_id):
                    raise SystemExit(1)
                values = {{
                    "{{{{.Name}}}}": "/" + name,
                    "{{{{.Id}}}}": container_id,
                    "{{{{.State.Running}}}}": running,
                    "{{{{.HostConfig.LogConfig.Type}}}}": "json-file",
                    "{{{{.LogPath}}}}": str(log_path),
                }}
                print(values[template])
                raise SystemExit(0)
            target = args[-1]
            raise SystemExit(0 if present.exists() and target in (name, container_id) else 1)
        """).lstrip(), encoding="utf-8")
        fake_docker.chmod(0o700)
        environment = os.environ.copy()
        environment.update({
            "SUB2API_DEPLOY_DATA_DIR": str(data_dir),
            "SUB2API_NGINX_LOG_DIR": str(nginx_dir),
            "SUB2API_LOG_RECHECK_SECONDS": "0",
            "SUB2API_CLEANUP_TEST_ROOT": str(root),
            "SUB2API_CLEANUP_DOCKER_BIN": str(fake_docker),
            "SUB2API_CLEANUP_DOCKER_SOCKET": str(root / "docker.sock"),
            "FAKE_DOCKER_ROOT": str(root / "docker"),
            "FAKE_CONTAINER_PRESENT": str(root / "container-present"),
            "FAKE_CONTAINER_RUNNING": "false",
        })
        return environment

    def run_script(self, mode, environment, *, include_legacy=True):
        if mode == "record":
            command = ["bash", CLEANUP, "--apply", "--stage", "record"]
        else:
            command = ["bash", CLEANUP, mode]
        if include_legacy:
            command.extend(("--legacy-container", LEGACY_NAME))
        return subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def prepare_root(self, root):
        data_dir = root / "data"
        nginx_dir = root / "nginx"
        data_dir.mkdir()
        nginx_dir.mkdir()
        docker_root = root / "docker"
        log_dir = docker_root / "containers" / CONTAINER_ID
        log_dir.mkdir(parents=True)
        log_path = log_dir / f"{CONTAINER_ID}-json.log"
        log_path.write_text("temporary Docker log sentinel", encoding="utf-8")
        present = root / "container-present"
        present.touch()
        return data_dir, nginx_dir, log_path, present

    def record_then_remove(self, environment, log_path, present):
        result = self.run_script("record", environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(str(log_path), result.stdout + result.stderr)
        present.unlink()
        log_path.unlink()
        log_path.parent.rmdir()

    def test_default_check_is_read_only_does_not_require_or_access_docker(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            data_dir, nginx_dir, _, _ = self.prepare_root(root)
            business_log = data_dir / "sub2api-response-debug.log"
            business_log.write_text("temporary test sentinel", encoding="utf-8")
            marker = root / "docker-called"
            fake_docker = root / "fake-docker"
            fake_docker.write_text(
                f"#!/bin/sh\ntouch {marker}\nexit 99\n", encoding="utf-8"
            )
            fake_docker.chmod(0o700)
            environment = self.environment(root, data_dir, nginx_dir)
            environment["SUB2API_CLEANUP_DOCKER_BIN"] = str(fake_docker)
            result = self.run_script("check", environment, include_legacy=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("check only", result.stdout)
        self.assertIn("conversation-capable log files were found", result.stdout)
        self.assertNotIn(str(business_log), result.stdout + result.stderr)
        self.assertFalse(marker.exists())

    def test_apply_requires_explicit_legacy_container_name(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            data_dir, nginx_dir, _, _ = self.prepare_root(root)
            result = self.run_script(
                "--apply",
                self.environment(root, data_dir, nginx_dir),
                include_legacy=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicit valid legacy container name", result.stderr)

    def test_record_stage_cannot_write_without_explicit_apply(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            data_dir, nginx_dir, _, _ = self.prepare_root(root)
            environment = self.environment(root, data_dir, nginx_dir)
            result = subprocess.run(
                [
                    "bash",
                    CLEANUP,
                    "check",
                    "--stage",
                    "record",
                    "--legacy-container",
                    LEGACY_NAME,
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires explicit --apply", result.stderr)

    def test_apply_rejects_data_directory_without_data_basename(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            _, nginx_dir, _, _ = self.prepare_root(root)
            unsafe_data = root / "etc"
            unsafe_data.mkdir()
            sentinel = unsafe_data / "sub2api-response-debug.log"
            sentinel.write_text("temporary test sentinel", encoding="utf-8")
            result = self.run_script(
                "--apply", self.environment(root, unsafe_data, nginx_dir)
            )
            sentinel_survived = sentinel.exists()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("data directory does not resolve", result.stderr)
        self.assertTrue(sentinel_survived)

    def test_apply_rejects_nginx_directory_without_nginx_basename(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            data_dir, _, _, _ = self.prepare_root(root)
            unsafe_nginx = root / "var-log"
            unsafe_nginx.mkdir()
            sentinel = unsafe_nginx / "sub2api-capture.log"
            sentinel.write_text("temporary test sentinel", encoding="utf-8")
            result = self.run_script(
                "--apply", self.environment(root, data_dir, unsafe_nginx)
            )
            sentinel_survived = sentinel.exists()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Nginx log directory does not resolve", result.stderr)
        self.assertTrue(sentinel_survived)

    def test_record_rejects_unvalidated_docker_log_path(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            data_dir, nginx_dir, log_path, _ = self.prepare_root(root)
            log_path.rename(root / "unexpected-json.log")
            result = self.run_script(
                "record", self.environment(root, data_dir, nginx_dir)
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LogPath failed validation", result.stderr)
        self.assertNotIn(str(log_path), result.stdout + result.stderr)

    def test_record_requires_the_legacy_container_to_be_stopped(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            data_dir, nginx_dir, log_path, _ = self.prepare_root(root)
            environment = self.environment(root, data_dir, nginx_dir)
            environment["FAKE_CONTAINER_RUNNING"] = "true"
            result = self.run_script("record", environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be stopped", result.stderr)
        self.assertNotIn(str(log_path), result.stdout + result.stderr)

    def test_apply_rejects_container_that_still_exists(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            data_dir, nginx_dir, log_path, _ = self.prepare_root(root)
            environment = self.environment(root, data_dir, nginx_dir)
            record = self.run_script("record", environment)
            self.assertEqual(record.returncode, 0, record.stderr)
            result = self.run_script("--apply", environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("legacy container still exists", result.stderr)
        self.assertNotIn(str(log_path), result.stdout + result.stderr)

    def test_apply_rejects_recorded_log_path_that_survived_container_removal(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            data_dir, nginx_dir, log_path, present = self.prepare_root(root)
            environment = self.environment(root, data_dir, nginx_dir)
            record = self.run_script("record", environment)
            self.assertEqual(record.returncode, 0, record.stderr)
            present.unlink()
            result = self.run_script("--apply", environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("recorded legacy Docker LogPath still exists", result.stderr)
        self.assertNotIn(str(log_path), result.stdout + result.stderr)

    def test_apply_rejects_a_leftover_container_log_directory(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            data_dir, nginx_dir, log_path, present = self.prepare_root(root)
            environment = self.environment(root, data_dir, nginx_dir)
            record = self.run_script("record", environment)
            self.assertEqual(record.returncode, 0, record.stderr)
            present.unlink()
            log_path.unlink()
            result = self.run_script("--apply", environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("container log directory still exists", result.stderr)
        self.assertNotIn(str(log_path.parent), result.stdout + result.stderr)

    def test_record_remove_apply_and_verify_complete_without_path_disclosure(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            data_dir, nginx_dir, log_path, present = self.prepare_root(root)
            data_log = data_dir / "sub2api-response-debug.log"
            nginx_log = nginx_dir / "sub2api-capture.log"
            data_log.write_text("temporary test sentinel", encoding="utf-8")
            nginx_log.write_text("temporary test sentinel", encoding="utf-8")
            environment = self.environment(root, data_dir, nginx_dir)
            self.record_then_remove(environment, log_path, present)
            applied = self.run_script("--apply", environment)
            verified = self.run_script("verify", environment)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertFalse(data_log.exists())
        self.assertFalse(nginx_log.exists())
        combined = applied.stdout + applied.stderr + verified.stdout + verified.stderr
        self.assertNotIn(str(log_path), combined)

    def test_invalid_recheck_delay_fails_before_deleting_business_logs(self):
        with tempfile.TemporaryDirectory(dir="/tmp", prefix="sub2api-gate-cleanup-") as directory:
            root = pathlib.Path(directory)
            data_dir, nginx_dir, log_path, present = self.prepare_root(root)
            business_log = data_dir / "sub2api-response-debug.log"
            business_log.write_text("temporary test sentinel", encoding="utf-8")
            environment = self.environment(root, data_dir, nginx_dir)
            self.record_then_remove(environment, log_path, present)
            environment["SUB2API_LOG_RECHECK_SECONDS"] = "invalid"
            result = self.run_script("--apply", environment)
            survived = business_log.exists()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be an integer", result.stderr)
        self.assertTrue(survived)

    def test_script_never_deletes_the_recorded_docker_log_path(self):
        source = CLEANUP.read_text(encoding="utf-8")
        self.assertNotIn('rm "$record_path"', source)
        self.assertNotIn('find "$record_root"', source)
        self.assertNotIn('find "$record_path"', source)
        self.assertIn('[ -e "$record_path" ]', source)
        self.assertIn('[ -e "$record_container_directory" ]', source)


if __name__ == "__main__":
    unittest.main()
