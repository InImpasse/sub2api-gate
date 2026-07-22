#!/usr/bin/env python3
import argparse
import os
import pathlib
import re
import stat
import sys


class VerificationError(RuntimeError):
    pass


def read_proc_file(path, maximum_bytes):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise VerificationError("process metadata is not a regular file")
        payload = os.read(descriptor, maximum_bytes + 1)
        if len(payload) > maximum_bytes:
            raise VerificationError("process metadata exceeds its size limit")
    finally:
        os.close(descriptor)
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise VerificationError("process metadata is not ASCII") from error


def parse_core_limits(payload):
    for line in payload.splitlines():
        fields = line.split()
        if fields[:4] != ["Max", "core", "file", "size"]:
            continue
        if len(fields) != 7 or fields[6] != "bytes":
            raise VerificationError("nginx core limits could not be parsed")
        return fields[4], fields[5]
    raise VerificationError("nginx core limits are missing")


def verify_runtime_limits(proc_root=pathlib.Path("/proc")):
    try:
        entries = sorted(
            (entry for entry in pathlib.Path(proc_root).iterdir() if entry.name.isdigit()),
            key=lambda entry: int(entry.name),
        )
    except OSError as error:
        raise VerificationError("process table could not be read") from error

    saw_nginx = False
    verified = 0
    for process in entries:
        try:
            command = read_proc_file(process / "comm", 64).strip()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            raise VerificationError("process identity could not be read") from error
        if command != "nginx":
            continue
        saw_nginx = True
        try:
            limits = read_proc_file(process / "limits", 16 * 1024)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            raise VerificationError("nginx process limits could not be read") from error
        soft, hard = parse_core_limits(limits)
        if soft != "0" or hard != "0":
            raise VerificationError("nginx core soft and hard limits must both be zero")
        verified += 1

    if verified == 0:
        message = "no stable nginx process was found" if saw_nginx else "no nginx process was found"
        raise VerificationError(message)
    return verified


def verify_tracked_contract(repo_root):
    root = pathlib.Path(repo_root)
    try:
        nginx_config = (root / "nginx" / "test-nginx.conf").read_text(encoding="ascii")
        drop_in = (root / "nginx" / "systemd" / "nginx-core-limit.conf").read_text(
            encoding="ascii",
        )
    except (OSError, UnicodeError) as error:
        raise VerificationError("tracked nginx core-dump contract could not be read") from error

    directives = re.findall(
        r"(?m)^\s*worker_rlimit_core\s+([^;]+);\s*(?:#.*)?$",
        nginx_config,
    )
    events_offset = nginx_config.find("events {")
    directive_offset = nginx_config.find("worker_rlimit_core 0;")
    if directives != ["0"] or events_offset < 0 or not 0 <= directive_offset < events_offset:
        raise VerificationError("worker_rlimit_core must be zero in the nginx main context")
    if drop_in != "[Service]\nLimitCORE=0\n":
        raise VerificationError("the nginx systemd core limit must set LimitCORE to zero")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verify that Nginx cannot write core dumps")
    parser.add_argument("mode", nargs="?", choices=("check", "verify"), default="check")
    args = parser.parse_args(argv)
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    try:
        verify_tracked_contract(repo_root)
        if args.mode == "verify":
            verify_runtime_limits()
    except VerificationError as error:
        print(f"nginx core-dump verification failed: {error}", file=sys.stderr)
        return 1
    print("nginx core-dump verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
