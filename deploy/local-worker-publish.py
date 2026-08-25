#!/usr/bin/python3 -I
"""Publish a reviewed Worker release using the operator's local Wrangler OAuth login.

This is deliberately separate from the root-only cc publisher. It stages one
of the reviewed source commits in a temporary Git worktree and never accepts
or writes a Worker Secret. Secret values are read only by Wrangler itself; the
controller passes its name-only JSON directly to the existing verifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
COMPATIBILITY_RELEASE = "b0536687d88fdb0031503c41c7aaebc56bb12a59"
FINAL_SOURCE_RELEASE = "f805877b8c8c82e40f21b20967b5981adea8491c"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_TOOLCHAIN_BYTES = 8 * 1024 * 1024
REVIEWED_TOOLCHAIN_SHA256 = {
    "package.json": "a3d11acfccda4e2776ccee98650d34d600df4d3eb9cd5532bb3cd2d8dc782790",
    "package-lock.json": "408a8d2623a8950282eab6ba96998a57d27380f10df8dc01e5821e11056d2721",
}
MINIFLARE_VERSION = "4.20260714.0"
UNDICI_VERSION = "7.29.0"
SHARP_VERSION = "0.35.3"
REMOTE_OUTCOME_UNKNOWN = (
    "remote_outcome_unknown: Worker publish may have completed; "
    "verify the exact remote deployment before retrying"
)


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


def sha256_file(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_reviewed_toolchain(path, expected_hash):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise LocalPublishError("reviewed Worker toolchain manifest is unavailable") from error
    if target.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise LocalPublishError("reviewed Worker toolchain manifest must be a single-link regular file")
    if metadata.st_size > MAX_TOOLCHAIN_BYTES:
        raise LocalPublishError("reviewed Worker toolchain manifest is too large")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise LocalPublishError("reviewed Worker toolchain manifest could not be opened") from error
    try:
        opened = os.fstat(descriptor)
        payload = os.read(descriptor, MAX_TOOLCHAIN_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or len(payload) > MAX_TOOLCHAIN_BYTES
        or (metadata.st_dev, metadata.st_ino, metadata.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or hashlib.sha256(payload).hexdigest() != expected_hash
    ):
        raise LocalPublishError("reviewed Worker toolchain hash does not match the approved candidate")
    return payload


def _validate_reviewed_toolchain(package_payload, lock_payload):
    try:
        package = json.loads(package_payload.decode("utf-8", "strict"))
        lock = json.loads(lock_payload.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LocalPublishError("reviewed Worker toolchain manifests must be valid JSON") from error
    expected_dependencies = {
        "miniflare": MINIFLARE_VERSION,
        "wrangler": WRANGLER_VERSION,
    }
    dependencies = package.get("devDependencies")
    lock_packages = lock.get("packages")
    if (
        not isinstance(dependencies, dict)
        or any(dependencies.get(name) != version for name, version in expected_dependencies.items())
        or package.get("overrides") != {"undici": UNDICI_VERSION, "sharp": SHARP_VERSION}
        or not isinstance(lock_packages, dict)
        or any(lock_packages.get("", {}).get("devDependencies", {}).get(name) != version for name, version in expected_dependencies.items())
        or lock_packages.get("node_modules/miniflare", {}).get("version") != MINIFLARE_VERSION
        or lock_packages.get("node_modules/wrangler", {}).get("version") != WRANGLER_VERSION
        or lock_packages.get("node_modules/undici", {}).get("version") != UNDICI_VERSION
    ):
        raise LocalPublishError("reviewed Worker toolchain dependency pins do not match policy")


def _replace_staged_manifest(path, payload):
    target = pathlib.Path(path)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise LocalPublishError("staged Worker toolchain manifest is unavailable") from error
    if target.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise LocalPublishError("staged Worker toolchain manifest must be a regular file")
    temporary = target.with_name(f".{target.name}.reviewed")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temporary, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o644)
            written = 0
            while written < len(payload):
                written += os.write(descriptor, payload[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, target)
    except OSError as error:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise LocalPublishError("reviewed Worker toolchain could not be staged") from error


def overlay_reviewed_toolchain(repo_dir, stage_dir):
    source_worker = pathlib.Path(repo_dir) / WORKER_RELATIVE
    staged_worker = pathlib.Path(stage_dir) / WORKER_RELATIVE
    payloads = {
        name: _read_reviewed_toolchain(source_worker / name, expected_hash)
        for name, expected_hash in REVIEWED_TOOLCHAIN_SHA256.items()
    }
    _validate_reviewed_toolchain(payloads["package.json"], payloads["package-lock.json"])
    for name, payload in payloads.items():
        _replace_staged_manifest(staged_worker / name, payload)
        if sha256_file(staged_worker / name) != REVIEWED_TOOLCHAIN_SHA256[name]:
            raise LocalPublishError("staged Worker toolchain hash does not match the approved candidate")
    return dict(REVIEWED_TOOLCHAIN_SHA256)


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
        try:
            result = run_command(runner, command.arguments, cwd=stage, environment=environment)
        except (LocalPublishError, OSError, subprocess.SubprocessError) as error:
            if command.label == "deploy":
                raise LocalPublishError(REMOTE_OUTCOME_UNKNOWN) from error
            raise
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


def run_staged_publish(
    repo_dir,
    stage_dir,
    spec,
    private_config,
    node,
    home,
    *,
    apply,
    runner=subprocess.run,
    expected_uid=None,
):
    owner = os.geteuid() if expected_uid is None else expected_uid
    stage_release(repo_dir, stage_dir, spec, runner=runner)
    try:
        overlay_reviewed_toolchain(repo_dir, stage_dir)
        copy_private_config(
            private_config,
            pathlib.Path(stage_dir) / PRIVATE_CONFIG_RELATIVE,
            expected_uid=owner,
        )
        run_publish_plan(stage_dir, spec, node, home, apply=apply, runner=runner)
    finally:
        remove_stage(repo_dir, stage_dir, runner=runner)


def main(argv=None, *, runner=subprocess.run):
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("check",), nargs="?")
    parser.add_argument("--apply", action="store_true", help="publish the reviewed Worker release after all gates pass")
    parser.add_argument("--totp-rotation-stage", choices=("compatibility", "stage", "promoted", "final-source"), default="compatibility")
    parser.add_argument("--node", type=pathlib.Path, default=pathlib.Path(shutil.which("node") or ""))
    parser.add_argument("--home", type=pathlib.Path, default=pathlib.Path(os.environ.get("HOME", "")))
    parser.add_argument("--wrangler-config", type=pathlib.Path, default=ROOT / PRIVATE_CONFIG_RELATIVE)
    arguments = parser.parse_args(argv)
    if arguments.mode == "check" and arguments.apply:
        parser.error("'check' cannot be combined with --apply")
    try:
        if os.geteuid() == 0:
            raise LocalPublishError("local Worker publishing must run as the OAuth-owning operator")
        try:
            node = arguments.node.resolve(strict=True)
        except OSError as error:
            raise LocalPublishError("local Node executable is unavailable") from error
        if not node.is_file() or not os.access(node, os.X_OK):
            raise LocalPublishError("local Node executable is unavailable")
        if not arguments.home.is_dir() or not arguments.home.is_absolute():
            raise LocalPublishError("local Wrangler OAuth home is unavailable")
        require_private_config(arguments.wrangler_config, expected_uid=os.geteuid())
        spec = release_spec(arguments.totp_rotation_stage)
        with tempfile.TemporaryDirectory(prefix="sub2api-worker-release-") as temporary:
            stage = pathlib.Path(temporary) / "release"
            run_staged_publish(
                ROOT,
                stage,
                spec,
                arguments.wrangler_config,
                node,
                arguments.home,
                apply=arguments.apply,
                runner=runner,
                expected_uid=os.geteuid(),
            )
        print("local Worker publish completed" if arguments.apply else "local Worker publish check passed; no Worker was published")
        return 0
    except (LocalPublishError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
