#!/usr/bin/python3 -I
"""Publish a reviewed Worker release using the operator's local Wrangler OAuth login.

This is deliberately separate from the root-only cc publisher. It stages one
of the reviewed source commits in a temporary Git worktree and never accepts
or writes a Worker Secret. Secret values are read only by Wrangler itself; the
controller passes its name-only JSON directly to the existing verifier.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKER_RELATIVE = pathlib.Path("worker-allow-ip")
PRIVATE_CONFIG_RELATIVE = WORKER_RELATIVE / "wrangler.private.jsonc"
WRANGLER_ENTRY_RELATIVE = WORKER_RELATIVE / "node_modules/wrangler/bin/wrangler.js"
REQUIRED_SECRETS_RELATIVE = WORKER_RELATIVE / "required-secrets.json"
WRANGLER_VERSION = "4.112.0"
COMPATIBILITY_RELEASE = "e5b6104bc8a8ec6f920a811de83e51310c6b5874"
FINAL_SOURCE_RELEASE = "f805877b8c8c82e40f21b20967b5981adea8491c"
MAX_CONFIG_BYTES = 1024 * 1024


class LocalPublishError(RuntimeError):
    pass


class ReleaseSpec:
    def __init__(self, commit, secret_requirement, *, verify_final_source=False):
        self.commit = commit
        self.secret_requirement = secret_requirement
        self.verify_final_source = verify_final_source


class PublishCommand:
    def __init__(self, label, arguments, *, output_label):
        self.label = label
        self.arguments = tuple(str(argument) for argument in arguments)
        self.output_label = output_label


def release_spec(stage):
    if stage == "compatibility":
        return ReleaseSpec(COMPATIBILITY_RELEASE, "--forbid-totp-rotation-staging")
    if stage in {"stage", "promoted"}:
        return ReleaseSpec(COMPATIBILITY_RELEASE, "--require-totp-rotation-staging")
    if stage == "final-source":
        return ReleaseSpec(
            FINAL_SOURCE_RELEASE,
            "--require-totp-rotation-staging",
            verify_final_source=True,
        )
    raise LocalPublishError("unsupported local Worker TOTP rotation stage")


def require_private_config(path, *, expected_uid):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise LocalPublishError("private Wrangler config is unavailable") from error
    if target.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise LocalPublishError("private Wrangler config must be a regular file")
    if metadata.st_uid != expected_uid:
        raise LocalPublishError("private Wrangler config must be owned by the local operator")
    if metadata.st_nlink != 1:
        raise LocalPublishError("private Wrangler config must be a single-link file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise LocalPublishError("private Wrangler config must be mode-0600")
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise LocalPublishError("private Wrangler config is too large")
    return metadata


def read_private_config(path, *, expected_uid):
    before = require_private_config(path, expected_uid=expected_uid)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LocalPublishError("private Wrangler config could not be opened") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != expected_uid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size > MAX_CONFIG_BYTES
        ):
            raise LocalPublishError("private Wrangler config is unsafe")
        payload = os.read(descriptor, MAX_CONFIG_BYTES + 1)
        after = os.fstat(descriptor)
        if len(payload) > MAX_CONFIG_BYTES or (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ) != (after.st_dev, after.st_ino, after.st_size):
            raise LocalPublishError("private Wrangler config changed while being read")
        return payload
    finally:
        os.close(descriptor)


def copy_private_config(source, destination, *, expected_uid):
    payload = read_private_config(source, expected_uid=expected_uid)
    target = pathlib.Path(destination)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as error:
        raise LocalPublishError("staged private Wrangler config could not be created") from error
    try:
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_wrangler_environment(node_path, home):
    node = pathlib.Path(node_path)
    home = pathlib.Path(home)
    if not node.is_absolute() or not home.is_absolute():
        raise LocalPublishError("local Node and OAuth home paths must be absolute")
    return {
        "PATH": f"{node.parent}:/usr/bin:/bin",
        "HOME": str(home),
        "WRANGLER_SEND_METRICS": "false",
        "CLOUDFLARE_INCLUDE_PROCESS_ENV": "false",
        "CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV": "false",
    }


def build_publish_plan(stage_dir, spec, node_path, *, apply=True):
    stage = pathlib.Path(stage_dir)
    node = pathlib.Path(node_path)
    worker = stage / WORKER_RELATIVE
    wrangler = stage / WRANGLER_ENTRY_RELATIVE
    npm = node.parent / "npm"
    config = worker / "wrangler.private.jsonc"
    manifest = stage / REQUIRED_SECRETS_RELATIVE
    commands = [
        PublishCommand("verify-node", [node, "--version"], output_label="Node version"),
        PublishCommand("install-dependencies", [npm, "--prefix", worker, "ci", "--ignore-scripts"], output_label="Worker dependencies"),
        PublishCommand("audit-dependencies", [npm, "--prefix", worker, "audit", "--audit-level=high", "--package-lock-only", "--ignore-scripts"], output_label="Worker dependency audit"),
        PublishCommand("run-tests", [npm, "--prefix", worker, "test"], output_label="Worker tests"),
        PublishCommand("verify-wrangler", [node, wrangler, "--version"], output_label="Wrangler version"),
        PublishCommand("validate-config", [node, stage / "deploy/validate-wrangler-config.mjs", config, manifest], output_label="private Wrangler config"),
    ]
    if spec.verify_final_source:
        commands.append(PublishCommand("verify-final-source", [node, stage / "deploy/verify-final-worker-totp-source.mjs", worker / "src"], output_label="final Worker source"))
    commands.append(PublishCommand("verify-secret-names", [node, stage / "deploy/verify-worker-secret-list.mjs", manifest, spec.secret_requirement], output_label="remote name validation"))
    commands.append(PublishCommand("deploy-dry-run", [node, wrangler, "deploy", "--dry-run", "--config", config], output_label="Worker dry-run"))
    if apply:
        commands.append(PublishCommand("deploy", [node, wrangler, "deploy", "--config", config], output_label="Worker publish"))
    return tuple(commands)


def run_command(runner, arguments, *, cwd, environment, input_text=None):
    result = runner(
        list(map(str, arguments)),
        cwd=str(cwd),
        env=environment,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise LocalPublishError("local Worker publish gate failed")
    return result


def verify_node_version(node_version):
    try:
        major = int(node_version.removeprefix("v").split(".", 1)[0])
    except ValueError:
        major = 0
    if not node_version.startswith("v") or major < 22:
        raise LocalPublishError("Node.js 22 or newer is required")


def verify_node_and_wrangler(node_version, wrangler_version):
    verify_node_version(node_version)
    if wrangler_version.strip() != WRANGLER_VERSION:
        raise LocalPublishError(f"locked Wrangler {WRANGLER_VERSION} is required")


def run_publish_plan(stage_dir, spec, node_path, home, *, apply, runner=subprocess.run):
    stage = pathlib.Path(stage_dir)
    environment = build_wrangler_environment(node_path, home)
    commands = build_publish_plan(stage, spec, node_path, apply=apply)
    secret_list = None
    node_version = None
    wrangler_version = None
    for command in commands:
        if command.label == "verify-secret-names":
            if not apply:
                continue
            worker = stage / WORKER_RELATIVE
            listed = run_command(
                runner,
                [node_path, stage / WRANGLER_ENTRY_RELATIVE, "secret", "list", "--format", "json", "--config", worker / "wrangler.private.jsonc"],
                cwd=stage,
                environment=environment,
            )
            secret_list = listed.stdout
            run_command(runner, command.arguments, cwd=stage, environment=environment, input_text=secret_list)
            secret_list = None
            continue
        result = run_command(runner, command.arguments, cwd=stage, environment=environment)
        if command.label == "verify-node":
            node_version = result.stdout.strip()
            verify_node_version(node_version)
        elif command.label == "verify-wrangler":
            wrangler_version = result.stdout.strip()
            verify_node_and_wrangler(node_version or "", wrangler_version)


def git_output(runner, arguments, *, cwd):
    result = run_command(runner, ["/usr/bin/git", *arguments], cwd=cwd, environment={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"})
    return result.stdout.strip()


def stage_release(repo_dir, stage_dir, spec, *, runner=subprocess.run):
    repo = pathlib.Path(repo_dir).resolve()
    git_output(runner, ["-C", repo, "rev-parse", "--is-inside-work-tree"], cwd=repo)
    commit = git_output(runner, ["-C", repo, "rev-parse", "--verify", f"{spec.commit}^{{commit}}"], cwd=repo)
    if commit != spec.commit:
        raise LocalPublishError("reviewed Worker release commit is unavailable")
    created = False
    try:
        run_command(
            runner,
            ["/usr/bin/git", "-C", repo, "worktree", "add", "--detach", stage_dir, spec.commit],
            cwd=repo,
            environment={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        )
        created = True
        staged_head = git_output(runner, ["-C", stage_dir, "rev-parse", "HEAD"], cwd=stage_dir)
        if staged_head != spec.commit:
            raise LocalPublishError("staged Worker release does not match the reviewed commit")
        status = git_output(runner, ["-C", stage_dir, "status", "--porcelain=v1", "--untracked-files=all"], cwd=stage_dir)
        if status:
            raise LocalPublishError("staged Worker release is not clean")
    except (LocalPublishError, OSError, subprocess.SubprocessError):
        if created:
            try:
                remove_stage(repo, stage_dir, runner=runner)
            except LocalPublishError:
                pass
        raise


def remove_stage(repo_dir, stage_dir, *, runner=subprocess.run):
    run_command(
        runner,
        ["/usr/bin/git", "-C", repo_dir, "worktree", "remove", "--force", stage_dir],
        cwd=repo_dir,
        environment={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
    )


def main(argv=None, *, runner=subprocess.run):
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("check", "--apply"), nargs="?", default="check")
    parser.add_argument("--totp-rotation-stage", choices=("compatibility", "stage", "promoted", "final-source"), default="compatibility")
    parser.add_argument("--node", type=pathlib.Path, default=pathlib.Path(shutil.which("node") or ""))
    parser.add_argument("--home", type=pathlib.Path, default=pathlib.Path(os.environ.get("HOME", "")))
    parser.add_argument("--wrangler-config", type=pathlib.Path, default=ROOT / PRIVATE_CONFIG_RELATIVE)
    arguments = parser.parse_args(argv)
    try:
        if os.geteuid() == 0:
            raise LocalPublishError("local Worker publishing must run as the OAuth-owning operator")
        node = arguments.node.resolve(strict=True)
        if not node.is_file() or not os.access(node, os.X_OK):
            raise LocalPublishError("local Node executable is unavailable")
        if not arguments.home.is_dir() or not arguments.home.is_absolute():
            raise LocalPublishError("local Wrangler OAuth home is unavailable")
        require_private_config(arguments.wrangler_config, expected_uid=os.geteuid())
        spec = release_spec(arguments.totp_rotation_stage)
        with tempfile.TemporaryDirectory(prefix="sub2api-worker-release-") as temporary:
            stage = pathlib.Path(temporary) / "release"
            stage_release(ROOT, stage, spec, runner=runner)
            copy_private_config(arguments.wrangler_config, stage / PRIVATE_CONFIG_RELATIVE, expected_uid=os.geteuid())
            try:
                run_publish_plan(stage, spec, node, arguments.home, apply=arguments.mode == "--apply", runner=runner)
            finally:
                remove_stage(ROOT, stage, runner=runner)
        print("local Worker publish completed" if arguments.mode == "--apply" else "local Worker publish check passed; no Worker was published")
        return 0
    except (LocalPublishError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
