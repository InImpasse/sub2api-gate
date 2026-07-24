import importlib.util
import os
import pathlib
import stat
import sys
import tempfile
import unittest

from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "harden-rpcbind.py"
SPEC = importlib.util.spec_from_file_location("rpcbind_hardening", SCRIPT)
HARDENING = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARDENING
SPEC.loader.exec_module(HARDENING)


RPCINFO_PORTMAPPER = b"""   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    4   udp    111  portmapper
"""


class FakeTTY:
    def __init__(self, value=True):
        self.value = value

    def isatty(self):
        return self.value


class FakeRunner:
    def __init__(
        self,
        *,
        service=None,
        socket=None,
        rpcinfo=RPCINFO_PORTMAPPER,
        reverse_services=None,
        keep_port_bound_after_stop=False,
        fail_start=False,
        fail_port_recovery=False,
    ):
        self.states = {
            HARDENING.TARGET_UNITS[0]: service or HARDENING.UnitState("enabled", "active"),
            HARDENING.TARGET_UNITS[1]: socket or HARDENING.UnitState("enabled", "active"),
        }
        self.rpcinfo = rpcinfo
        self.reverse_services = reverse_services or {}
        self.keep_port_bound_after_stop = keep_port_bound_after_stop
        self.fail_start = fail_start
        self.fail_port_recovery = fail_port_recovery
        self.port_bound = True
        self.calls = []

    def _result_for_status(self, value, active=False):
        if active:
            returncode = 0 if value == "active" else 3
        else:
            returncode = 0 if value in {"enabled", "enabled-runtime", "static", "indirect"} else 1
        return HARDENING.CommandResult(returncode, (value + "\n").encode("ascii"))

    def __call__(self, command, **_kwargs):
        command = tuple(command)
        self.calls.append(command)
        if command[0] == HARDENING.RPCINFO:
            return HARDENING.CommandResult(0, self.rpcinfo)
        if command[0] != HARDENING.SYSTEMCTL:
            raise AssertionError(f"unexpected command: {command}")
        operation = command[1]
        if operation == "show":
            unit = command[2]
            return HARDENING.CommandResult(
                0,
                f"Id={unit}\nLoadState=loaded\n".encode("ascii"),
            )
        if operation == "is-enabled":
            return self._result_for_status(self.states[command[2]].enabled)
        if operation == "is-active":
            return self._result_for_status(self.states[command[2]].active, active=True)
        if operation == "list-dependencies":
            unit = command[-1]
            entries = [unit, *self.reverse_services.get(unit, ())]
            return HARDENING.CommandResult(0, ("\n".join(entries) + "\n").encode("ascii"))
        if operation in {"enable", "disable", "start", "stop"}:
            runtime = "--runtime" in command
            units = [value for value in command[2:] if value != "--runtime"]
            if not units or any(value not in HARDENING.TARGET_UNITS for value in units):
                raise AssertionError(f"unexpected mutable command: {command}")
            if operation == "enable":
                for unit in units:
                    self.states[unit] = HARDENING.UnitState(
                        "enabled-runtime" if runtime else "enabled",
                        self.states[unit].active,
                    )
            elif operation == "disable":
                for unit in units:
                    self.states[unit] = HARDENING.UnitState(
                        "disabled-runtime" if runtime else "disabled",
                        self.states[unit].active,
                    )
            elif operation == "start":
                if self.fail_start:
                    return HARDENING.CommandResult(1)
                for unit in units:
                    self.states[unit] = HARDENING.UnitState(self.states[unit].enabled, "active")
                if not self.fail_port_recovery:
                    self.port_bound = True
            else:
                for unit in units:
                    self.states[unit] = HARDENING.UnitState(self.states[unit].enabled, "inactive")
                if not self.keep_port_bound_after_stop:
                    self.port_bound = False
            return HARDENING.CommandResult(0)
        raise AssertionError(f"unexpected command: {command}")


class RpcbindHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.proc_root = self.root / "proc"
        (self.proc_root / "net").mkdir(parents=True)
        self.mountinfo = self.root / "mountinfo"
        self.mountinfo.write_text(
            "24 20 0:22 / / rw,relatime - ext4 /dev/root rw\n",
            encoding="ascii",
        )
        self.set_port_tables()
        (self.root / "run").mkdir(mode=0o755)
        self.paths = HARDENING.HardeningPaths(
            repo_dir=self.root,
            trusted_release_root=self.root,
            clean_worktree=self.root / "clean-worktree",
            state_root=self.root / "run" / "sub2api-gate",
            state_path=self.root / "run" / "sub2api-gate" / "rpcbind-hardening-state.json",
            proc_root=self.proc_root,
            mountinfo_path=self.mountinfo,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )

    def tearDown(self):
        self.temporary.cleanup()

    def set_port_tables(self, *, bound=False, protocol="tcp"):
        header = "  sl  local_address rem_address   st\n"
        for name in ("tcp", "tcp6", "udp", "udp6"):
            row = ""
            if bound and name == protocol:
                row = "   0: 0100007F:006F 00000000:0000 0A\n"
            (self.proc_root / "net" / name).write_text(header + row, encoding="ascii")

    @staticmethod
    def port_for(runner):
        return lambda _paths: runner.port_bound

    def mutable_calls(self, runner):
        return [
            call
            for call in runner.calls
            if call[0] == HARDENING.SYSTEMCTL and call[1] in {"enable", "disable", "start", "stop"}
        ]

    def test_contract_is_limited_to_the_two_rpcbind_units(self):
        HARDENING.validate_contract(self.paths)
        self.assertEqual(HARDENING.TARGET_UNITS, ("rpcbind.service", "rpcbind.socket"))
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertTrue(source.startswith("#!/usr/bin/python3 -I\n"))
        self.assertNotIn("v2ray", source.lower())
        self.assertNotIn("xray", source.lower())

    def test_mountinfo_uses_the_controller_current_namespace(self):
        self.assertEqual(
            HARDENING.MOUNTINFO_PATH,
            HARDENING.PROC_ROOT / "self" / "mountinfo",
        )

    def test_trusted_release_tree_rejects_wrong_source_or_guard_identity(self):
        release_root = self.root / "opt" / "sub2api-gate-release"
        deploy_directory = release_root / "deploy"
        deploy_directory.mkdir(parents=True)
        source = deploy_directory / "harden-rpcbind.py"
        clean_worktree = deploy_directory / "require-clean-worktree.sh"
        source.write_text("#!/usr/bin/env python3\n", encoding="ascii")
        clean_worktree.write_text("#!/bin/bash\n", encoding="ascii")
        for path in (
            self.root / "opt",
            release_root,
            deploy_directory,
            source,
            clean_worktree,
        ):
            path.chmod(0o755)
        paths = HARDENING.dataclasses.replace(
            self.paths,
            repo_dir=release_root,
            trusted_release_root=release_root,
            clean_worktree=clean_worktree,
        )

        with mock.patch.object(HARDENING, "TRUSTED_RELEASE_ROOT", release_root), \
             mock.patch.object(HARDENING, "TRUSTED_RELEASE_PARENT", release_root.parent), \
             mock.patch.object(HARDENING, "TRUSTED_FILESYSTEM_ROOT", self.root):
            HARDENING.require_trusted_release_tree(
                paths,
                source_path=source,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            wrong_guard = deploy_directory / "different-guard.sh"
            wrong_guard.write_text("#!/bin/bash\n", encoding="ascii")
            wrong_guard.chmod(0o755)
            with self.assertRaisesRegex(
                HARDENING.RpcbindHardeningError, "clean worktree guard"
            ):
                HARDENING.require_trusted_release_tree(
                    HARDENING.dataclasses.replace(paths, clean_worktree=wrong_guard),
                    source_path=source,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )
            wrong_source = deploy_directory / "different-controller.py"
            wrong_source.write_text("#!/usr/bin/env python3\n", encoding="ascii")
            wrong_source.chmod(0o755)
            with self.assertRaisesRegex(
                HARDENING.RpcbindHardeningError, "controller source"
            ):
                HARDENING.require_trusted_release_tree(
                    paths,
                    source_path=wrong_source,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )

    def test_apply_checks_the_trusted_tree_before_running_the_worktree_guard(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertLess(
            source.index("require_trusted_release_tree(paths)"),
            source.index("require_clean_worktree(paths)"),
        )

    def test_nfs_mount_rejects_before_any_systemd_or_rpc_command(self):
        self.mountinfo.write_text(
            "24 20 0:22 / /mnt rw,relatime - nfs server:/export rw\n",
            encoding="ascii",
        )
        runner = FakeRunner()

        with self.assertRaisesRegex(HARDENING.RpcbindHardeningError, "NFS mounts"):
            HARDENING.inspect_safety_evidence(
                self.paths,
                runner=runner,
                port_inspector=self.port_for(runner),
            )

        self.assertEqual(runner.calls, [])

    def test_non_portmapper_rpc_program_rejects_before_state_or_mutation(self):
        runner = FakeRunner(
            rpcinfo=(
                RPCINFO_PORTMAPPER
                + b"    100003    4   tcp   2049  nfs\n"
            )
        )

        with self.assertRaisesRegex(HARDENING.RpcbindHardeningError, "registered RPC programs"):
            HARDENING.apply_hardening(
                self.paths,
                runner=runner,
                port_inspector=self.port_for(runner),
            )

        self.assertFalse(self.paths.state_path.exists())
        self.assertEqual(self.mutable_calls(runner), [])

    def test_reverse_service_dependency_rejects_before_state_or_mutation(self):
        runner = FakeRunner(
            reverse_services={HARDENING.TARGET_UNITS[0]: ("nfs-server.service",)}
        )

        with self.assertRaisesRegex(HARDENING.RpcbindHardeningError, "reverse systemd dependencies"):
            HARDENING.apply_hardening(
                self.paths,
                runner=runner,
                port_inspector=self.port_for(runner),
            )

        self.assertFalse(self.paths.state_path.exists())
        self.assertEqual(self.mutable_calls(runner), [])

    def test_reverse_non_service_dependency_rejects_before_state_or_mutation(self):
        for dependency in ("rpc-statd.socket", "remote-fs.target", "var-lib-nfs.mount"):
            with self.subTest(dependency=dependency):
                state_root = self.root / f"subtest-{dependency.replace('.', '-')}"
                paths = HARDENING.dataclasses.replace(
                    self.paths,
                    state_root=state_root,
                    state_path=state_root / "rpcbind-hardening-state.json",
                )
                runner = FakeRunner(
                    reverse_services={HARDENING.TARGET_UNITS[0]: (dependency,)}
                )

                with self.assertRaisesRegex(
                    HARDENING.RpcbindHardeningError,
                    "reverse systemd dependencies",
                ):
                    HARDENING.apply_hardening(
                        paths,
                        runner=runner,
                        port_inspector=self.port_for(runner),
                    )

                self.assertFalse(paths.state_path.exists())
                self.assertEqual(self.mutable_calls(runner), [])

    def test_malformed_reverse_dependency_output_rejects_before_state_or_mutation(self):
        runner = FakeRunner(
            reverse_services={HARDENING.TARGET_UNITS[0]: ("unexpected output",)}
        )

        with self.assertRaisesRegex(
            HARDENING.RpcbindHardeningError,
            "systemd dependency output is invalid",
        ):
            HARDENING.apply_hardening(
                self.paths,
                runner=runner,
                port_inspector=self.port_for(runner),
            )

        self.assertFalse(self.paths.state_path.exists())
        self.assertEqual(self.mutable_calls(runner), [])

    def test_apply_writes_root_private_state_and_only_mutates_rpcbind_targets(self):
        runner = FakeRunner()
        before = HARDENING.RpcbindState(
            service=runner.states[HARDENING.TARGET_UNITS[0]],
            socket=runner.states[HARDENING.TARGET_UNITS[1]],
        )

        changed = HARDENING.apply_hardening(
            self.paths,
            runner=runner,
            port_inspector=self.port_for(runner),
        )

        self.assertTrue(changed)
        state, port_bound, _identity = HARDENING.read_state(self.paths)
        self.assertTrue(port_bound)
        self.assertEqual(state, before)
        self.assertEqual(stat.S_IMODE(self.paths.state_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.paths.state_root.stat().st_mode), 0o700)
        self.assertEqual(
            runner.states[HARDENING.TARGET_UNITS[0]],
            HARDENING.UnitState("disabled", "inactive"),
        )
        self.assertEqual(
            runner.states[HARDENING.TARGET_UNITS[1]],
            HARDENING.UnitState("disabled", "inactive"),
        )
        for command in self.mutable_calls(runner):
            units = [value for value in command[2:] if value != "--runtime"]
            self.assertTrue(units)
            self.assertTrue(set(units).issubset(set(HARDENING.TARGET_UNITS)))

    def test_failure_restores_prior_state_and_removes_the_state_record(self):
        runner = FakeRunner(keep_port_bound_after_stop=True)
        before = dict(runner.states)

        with self.assertRaisesRegex(HARDENING.RpcbindHardeningError, "prior unit state was restored"):
            HARDENING.apply_hardening(
                self.paths,
                runner=runner,
                port_inspector=self.port_for(runner),
            )

        self.assertEqual(runner.states, before)
        self.assertFalse(self.paths.state_path.exists())
        self.assertIn((HARDENING.SYSTEMCTL, "enable", HARDENING.TARGET_UNITS[0]), runner.calls)
        self.assertIn((HARDENING.SYSTEMCTL, "start", HARDENING.TARGET_UNITS[1]), runner.calls)

    def test_failed_apply_keeps_recovery_state_when_port_111_does_not_return(self):
        runner = FakeRunner(fail_port_recovery=True)
        before = dict(runner.states)

        with mock.patch.object(
            HARDENING,
            "verify_hardened",
            side_effect=HARDENING.RpcbindHardeningError("simulated hardening failure"),
        ):
            with self.assertRaisesRegex(
                HARDENING.RpcbindHardeningError,
                "prior unit state could not be restored",
            ):
                HARDENING.apply_hardening(
                    self.paths,
                    runner=runner,
                    port_inspector=self.port_for(runner),
                )

        self.assertEqual(runner.states, before)
        self.assertFalse(runner.port_bound)
        self.assertTrue(self.paths.state_path.exists())
        state, port_bound, _identity = HARDENING.read_state(self.paths)
        self.assertEqual(
            state,
            HARDENING.RpcbindState(
                service=before[HARDENING.TARGET_UNITS[0]],
                socket=before[HARDENING.TARGET_UNITS[1]],
            ),
        )
        self.assertTrue(port_bound)

    def test_explicit_restore_replays_recorded_state_and_removes_record(self):
        runner = FakeRunner()
        before = dict(runner.states)
        HARDENING.apply_hardening(
            self.paths,
            runner=runner,
            port_inspector=self.port_for(runner),
        )
        self.assertTrue(self.paths.state_path.exists())

        changed = HARDENING.restore_hardening(
            self.paths,
            runner=runner,
            port_inspector=self.port_for(runner),
        )

        self.assertTrue(changed)
        self.assertEqual(runner.states, before)
        self.assertFalse(self.paths.state_path.exists())

    def test_previously_hardened_rpcbind_is_a_noop_without_a_state_record(self):
        runner = FakeRunner(
            service=HARDENING.UnitState("disabled", "inactive"),
            socket=HARDENING.UnitState("disabled", "inactive"),
        )
        runner.port_bound = False

        changed = HARDENING.apply_hardening(
            self.paths,
            runner=runner,
            port_inspector=self.port_for(runner),
        )

        self.assertFalse(changed)
        self.assertFalse(self.paths.state_path.exists())
        self.assertEqual(self.mutable_calls(runner), [])

    def test_tcp_and_udp_port_111_inspection_is_fail_closed(self):
        self.set_port_tables(bound=True, protocol="udp6")
        self.assertTrue(HARDENING.port_111_is_bound(self.paths))
        with self.assertRaisesRegex(HARDENING.RpcbindHardeningError, "port 111 remains bound"):
            HARDENING.verify_port_111_absent(self.paths)

    def test_apply_context_requires_root_trusted_release_and_private_tty(self):
        outside = HARDENING.dataclasses.replace(self.paths, repo_dir=self.root / "outside")
        with self.assertRaisesRegex(HARDENING.RpcbindHardeningError, "trusted production release tree"):
            HARDENING.require_production_apply_context(
                outside,
                streams=(FakeTTY(), FakeTTY(), FakeTTY()),
            )
        production_like = HARDENING.dataclasses.replace(
            self.paths,
            repo_dir=self.paths.trusted_release_root,
        )
        with mock.patch.object(HARDENING.os, "geteuid", return_value=0), \
             mock.patch.object(HARDENING, "require_safe_system_binary"), \
             mock.patch.object(HARDENING, "require_trusted_release_tree", create=True):
            with self.assertRaisesRegex(HARDENING.RpcbindHardeningError, "private interactive TTY"):
                HARDENING.require_production_apply_context(
                    production_like,
                    streams=(FakeTTY(), FakeTTY(False), FakeTTY()),
                )


if __name__ == "__main__":
    unittest.main()
