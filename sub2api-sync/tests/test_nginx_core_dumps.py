import importlib.util
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "deploy" / "verify-nginx-core-dumps.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_nginx_core_dumps", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def limits_text(soft, hard):
    return (
        "Limit                     Soft Limit           Hard Limit           Units\n"
        f"Max core file size        {soft:<20} {hard:<20} bytes\n"
        "Max open files            1024                 4096                 files\n"
    )


class NginxCoreDumpVerifierTests(unittest.TestCase):
    def make_process(self, proc_root, pid, *, comm="nginx", soft="0", hard="0"):
        process = proc_root / str(pid)
        process.mkdir()
        (process / "comm").write_text(f"{comm}\n", encoding="ascii")
        (process / "limits").write_text(limits_text(soft, hard), encoding="ascii")
        return process

    def test_rejects_a_proc_tree_without_nginx(self):
        verifier = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            proc_root = pathlib.Path(directory)
            self.make_process(proc_root, 101, comm="python")
            with self.assertRaisesRegex(verifier.VerificationError, "no nginx process"):
                verifier.verify_runtime_limits(proc_root)

    def test_rejects_unlimited_or_partially_limited_core_dumps(self):
        verifier = load_verifier()
        cases = (("unlimited", "unlimited"), ("0", "unlimited"), ("unlimited", "0"))
        for soft, hard in cases:
            with self.subTest(soft=soft, hard=hard), tempfile.TemporaryDirectory() as directory:
                proc_root = pathlib.Path(directory)
                self.make_process(proc_root, 102, soft=soft, hard=hard)
                with self.assertRaisesRegex(verifier.VerificationError, "must both be zero"):
                    verifier.verify_runtime_limits(proc_root)

    def test_accepts_only_when_all_stable_nginx_processes_have_zero_limits(self):
        verifier = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            proc_root = pathlib.Path(directory)
            self.make_process(proc_root, 103)
            self.make_process(proc_root, 104)
            self.make_process(proc_root, 105, comm="other", soft="unlimited", hard="unlimited")
            self.assertEqual(verifier.verify_runtime_limits(proc_root), 2)

    def test_ignores_a_process_that_disappears_after_its_comm_is_read(self):
        verifier = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            proc_root = pathlib.Path(directory)
            self.make_process(proc_root, 106)
            disappearing = self.make_process(proc_root, 107)
            original = verifier.read_proc_file

            def race(path, maximum_bytes):
                if path == disappearing / "limits":
                    shutil.rmtree(disappearing)
                    raise FileNotFoundError(path)
                return original(path, maximum_bytes)

            with mock.patch.object(verifier, "read_proc_file", side_effect=race):
                self.assertEqual(verifier.verify_runtime_limits(proc_root), 1)

    def test_rejects_when_every_nginx_process_disappears_during_scan(self):
        verifier = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            proc_root = pathlib.Path(directory)
            disappearing = self.make_process(proc_root, 108)
            original = verifier.read_proc_file

            def race(path, maximum_bytes):
                if path == disappearing / "limits":
                    shutil.rmtree(disappearing)
                    raise FileNotFoundError(path)
                return original(path, maximum_bytes)

            with mock.patch.object(verifier, "read_proc_file", side_effect=race):
                with self.assertRaisesRegex(verifier.VerificationError, "no stable nginx process"):
                    verifier.verify_runtime_limits(proc_root)

    def test_tracked_contract_requires_main_context_and_systemd_hard_limit(self):
        verifier = load_verifier()
        verifier.verify_tracked_contract(ROOT)


if __name__ == "__main__":
    unittest.main()
