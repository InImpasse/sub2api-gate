#!/usr/bin/env python3
import base64
import binascii
import fcntl
import getpass
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import stat
import sys
import time


TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1
BASE32_PATTERN = re.compile(r"^[A-Z2-7]+$")
BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
ECMASCRIPT_TRIM_CHARACTERS = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff"
)
MIN_TOTP_SECRET_CHARACTERS = 16
MAX_TOTP_SECRET_CHARACTERS = 128
VERIFIER_VERSION = 1
VERIFIER_ALGORITHM = "pbkdf2-sha256"
VERIFIER_ITERATIONS = 310_000
VERIFIER_SALT_BYTES = 16
VERIFIER_DIGEST_BYTES = 32
MAX_VERIFIER_BYTES = 1024
MAX_REPLAY_STATE_BYTES = 128
REPLAY_STATE_VERSION = 1
MAX_TOTP_COUNTER = (1 << 63) - 1
REPLAY_LOCK_TIMEOUT_SECONDS = 5
DEFAULT_VERIFIER_PATH = pathlib.Path(
    "/mnt/data/sub2api-gate/private/admin-totp-verifier.json"
)


class TotpVerificationError(Exception):
    pass


def decode_base32_secret(secret):
    if not isinstance(secret, str):
        raise ValueError("invalid base32 secret")
    normalized = secret.strip(ECMASCRIPT_TRIM_CHARACTERS).upper()
    if (
        not MIN_TOTP_SECRET_CHARACTERS <= len(normalized) <= MAX_TOTP_SECRET_CHARACTERS
        or not BASE32_PATTERN.fullmatch(normalized)
    ):
        raise ValueError("invalid base32 secret")
    accumulator = 0
    bit_count = 0
    decoded = bytearray()
    for character in normalized:
        accumulator = (
            (accumulator << 5) | BASE32_ALPHABET.index(character)
        )
        bit_count += 5
        if bit_count >= 8:
            bit_count -= 8
            decoded.append((accumulator >> bit_count) & 0xFF)
            accumulator &= (1 << bit_count) - 1
    return bytes(decoded)


def _base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _registered_secret_digest(secret, salt, iterations=VERIFIER_ITERATIONS):
    return hashlib.pbkdf2_hmac(
        "sha256",
        decode_base32_secret(secret),
        salt,
        iterations,
        dklen=VERIFIER_DIGEST_BYTES,
    )


def build_registered_secret_verifier(secret, *, salt=None):
    verifier_salt = secrets.token_bytes(VERIFIER_SALT_BYTES) if salt is None else salt
    if not isinstance(verifier_salt, bytes) or len(verifier_salt) != VERIFIER_SALT_BYTES:
        raise ValueError("invalid verifier salt")
    digest = _registered_secret_digest(secret, verifier_salt)
    return {
        "version": VERIFIER_VERSION,
        "algorithm": VERIFIER_ALGORITHM,
        "iterations": VERIFIER_ITERATIONS,
        "salt": _base64url(verifier_salt),
        "digest": _base64url(digest),
    }


def _decode_base64url(value, expected_bytes):
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("invalid verifier encoding")
    try:
        decoded = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid verifier encoding") from error
    if len(decoded) != expected_bytes or _base64url(decoded) != value:
        raise ValueError("invalid verifier encoding")
    return decoded


def _validated_registered_secret_verifier(verifier):
    if not isinstance(verifier, dict) or set(verifier) != {
        "version", "algorithm", "iterations", "salt", "digest"
    }:
        raise ValueError("invalid registered secret verifier")
    if (
        type(verifier["version"]) is not int
        or verifier["version"] != VERIFIER_VERSION
        or type(verifier["iterations"]) is not int
        or verifier["algorithm"] != VERIFIER_ALGORITHM
        or verifier["iterations"] != VERIFIER_ITERATIONS
    ):
        raise ValueError("invalid registered secret verifier")
    salt = _decode_base64url(verifier["salt"], VERIFIER_SALT_BYTES)
    digest = _decode_base64url(verifier["digest"], VERIFIER_DIGEST_BYTES)
    return salt, digest


def verify_registered_totp(verifier, secret, code, now=None):
    return _matching_registered_totp_counter(
        verifier,
        secret,
        code,
        now=now,
    ) is not None


def _matching_registered_totp_counter(verifier, secret, code, now=None):
    try:
        salt, expected = _validated_registered_secret_verifier(verifier)
        actual = _registered_secret_digest(secret, salt)
        secret_matches = hmac.compare_digest(actual, expected)
        matched_counter = _matching_totp_counter(secret, code, now=now)
        if not secret_matches or matched_counter is None:
            return None
        return matched_counter
    except (TypeError, ValueError, OverflowError):
        return None


def _require_private_parent(path, expected_uid):
    path = pathlib.Path(path)
    if not path.is_absolute():
        raise TotpVerificationError("registered TOTP verifier path must be absolute")
    try:
        metadata = path.parent.lstat()
        resolved = path.parent.resolve(strict=True)
    except OSError as error:
        raise TotpVerificationError(
            "registered TOTP verifier directory is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or resolved != path.parent
    ):
        raise TotpVerificationError(
            "registered TOTP verifier directory must be operator-owned mode 0700"
        )
    return path


def _fsync_directory(path):
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _strict_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate verifier field")
        result[key] = value
    return result


def write_registered_secret_verifier(path, verifier, *, expected_uid):
    path = _require_private_parent(path, expected_uid)
    _validated_registered_secret_verifier(verifier)
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise TotpVerificationError("registered TOTP verifier is unsafe") from error
    else:
        raise TotpVerificationError("registered TOTP verifier already exists")

    payload = (
        json.dumps(verifier, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    if len(payload) > MAX_VERIFIER_BYTES:
        raise TotpVerificationError("registered TOTP verifier is invalid")
    temporary = path.parent / f".{path.name}.tmp-{secrets.token_hex(16)}"
    descriptor = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise TotpVerificationError(
                "registered TOTP verifier already exists"
            ) from error
        temporary.unlink()
        _fsync_directory(path.parent)
    except TotpVerificationError:
        raise
    except OSError as error:
        raise TotpVerificationError("registered TOTP verifier could not be created") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_registered_secret_verifier(path, *, expected_uid):
    path = _require_private_parent(path, expected_uid)
    descriptor = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAX_VERIFIER_BYTES
        ):
            raise TotpVerificationError("registered TOTP verifier is unsafe")
        chunks = []
        remaining = MAX_VERIFIER_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
        ):
            raise TotpVerificationError("registered TOTP verifier changed while reading")
        verifier = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_strict_json_object,
        )
        _validated_registered_secret_verifier(verifier)
        return verifier
    except TotpVerificationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise TotpVerificationError("registered TOTP verifier is invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _replay_paths(verifier_path):
    path = pathlib.Path(verifier_path)
    return (
        path.parent / f".{path.name}.replay.lock",
        path.parent / f".{path.name}.replay-state.json",
    )


def _open_replay_lock(path, *, expected_uid):
    flags = (
        os.O_RDWR
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
    )
    created = False
    try:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise TotpVerificationError(
                "privacy migration TOTP replay lock is unsafe"
            ) from error
    except OSError as error:
        raise TotpVerificationError(
            "privacy migration TOTP replay lock is unavailable"
        ) from error
    try:
        if created:
            os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 0
        ):
            raise TotpVerificationError(
                "privacy migration TOTP replay lock is unsafe"
            )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _acquire_replay_lock(
    descriptor,
    *,
    timeout_seconds=REPLAY_LOCK_TIMEOUT_SECONDS,
    clock=time.monotonic,
    sleeper=time.sleep,
):
    deadline = clock() + timeout_seconds
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            remaining = deadline - clock()
            if remaining <= 0:
                raise TotpVerificationError(
                    "privacy migration TOTP replay lock is unavailable"
                )
            sleeper(min(0.05, remaining))
        except OSError as error:
            raise TotpVerificationError(
                "privacy migration TOTP replay lock is unavailable"
            ) from error


def _replay_state_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_last_consumed_counter(path, *, expected_uid):
    descriptor = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError:
        return -1
    except OSError as error:
        raise TotpVerificationError(
            "privacy migration TOTP replay state is unsafe"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAX_REPLAY_STATE_BYTES
        ):
            raise TotpVerificationError(
                "privacy migration TOTP replay state is unsafe"
            )
        payload = os.read(descriptor, MAX_REPLAY_STATE_BYTES + 1)
        after = os.fstat(descriptor)
        if (
            len(payload) != before.st_size
            or _replay_state_identity(before) != _replay_state_identity(after)
        ):
            raise TotpVerificationError(
                "privacy migration TOTP replay state changed while reading"
            )
        state = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_strict_json_object,
        )
        if (
            not isinstance(state, dict)
            or set(state) != {"version", "last_counter"}
            or type(state["version"]) is not int
            or state["version"] != REPLAY_STATE_VERSION
            or type(state["last_counter"]) is not int
            or not 0 <= state["last_counter"] <= MAX_TOTP_COUNTER
        ):
            raise ValueError("invalid replay state")
        return state["last_counter"]
    except TotpVerificationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise TotpVerificationError(
            "privacy migration TOTP replay state is invalid"
        ) from error
    finally:
        os.close(descriptor)


def _write_last_consumed_counter(path, counter):
    if type(counter) is not int or not 0 <= counter <= MAX_TOTP_COUNTER:
        raise TotpVerificationError(
            "privacy migration TOTP replay state is invalid"
        )
    payload = (
        json.dumps(
            {"version": REPLAY_STATE_VERSION, "last_counter": counter},
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
    ).encode("ascii")
    temporary = path.parent / f".{path.name}.tmp-{secrets.token_hex(16)}"
    descriptor = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError as error:
        raise TotpVerificationError(
            "privacy migration TOTP replay state could not be recorded"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def verify_and_consume_registered_totp(
    verifier_path,
    secret,
    code,
    *,
    now=None,
    expected_uid=None,
):
    operator_uid = os.geteuid() if expected_uid is None else expected_uid
    path = _require_private_parent(verifier_path, operator_uid)
    lock_path, state_path = _replay_paths(path)
    lock_descriptor = _open_replay_lock(lock_path, expected_uid=operator_uid)
    try:
        _acquire_replay_lock(lock_descriptor)
        verifier = read_registered_secret_verifier(
            path,
            expected_uid=operator_uid,
        )
        matched_counter = _matching_registered_totp_counter(
            verifier,
            secret,
            code,
            now=now,
        )
        if matched_counter is None:
            raise TotpVerificationError(
                "privacy migration TOTP verification failed"
            )
        last_counter = _read_last_consumed_counter(
            state_path,
            expected_uid=operator_uid,
        )
        if matched_counter <= last_counter:
            raise TotpVerificationError(
                "privacy migration TOTP verification failed"
            )
        _write_last_consumed_counter(state_path, matched_counter)
    finally:
        os.close(lock_descriptor)


def hotp(secret, counter, digits=TOTP_DIGITS):
    if not isinstance(counter, int) or counter < 0:
        raise ValueError("invalid counter")
    if not isinstance(digits, int) or not 6 <= digits <= 10:
        raise ValueError("invalid code width")
    digest = hmac.new(
        decode_base32_secret(secret),
        counter.to_bytes(8, "big"),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def totp(secret, timestamp, digits=TOTP_DIGITS):
    counter = int(timestamp) // TOTP_PERIOD_SECONDS
    return hotp(secret, counter, digits=digits)


def _matching_totp_counter(secret, code, now=None, window=TOTP_WINDOW):
    supplied = str(code or "")
    if not supplied.isascii() or not supplied.isdigit() or len(supplied) != TOTP_DIGITS:
        return None
    if not isinstance(window, int) or window < 0 or window > TOTP_WINDOW:
        return None
    try:
        current_time = time.time() if now is None else float(now)
        current_counter = int(current_time) // TOTP_PERIOD_SECONDS
        matched_counter = None
        for offset in range(-window, window + 1):
            counter = current_counter + offset
            if counter < 0:
                continue
            candidate = hotp(secret, counter)
            if hmac.compare_digest(candidate, supplied):
                matched_counter = counter
    except (TypeError, ValueError, OverflowError):
        return None
    return matched_counter


def verify_totp(secret, code, now=None, window=TOTP_WINDOW):
    return _matching_totp_counter(
        secret,
        code,
        now=now,
        window=window,
    ) is not None


def _require_private_tty():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise TotpVerificationError("privacy migration TOTP requires an interactive TTY")


def enroll_interactive(
    verifier_path=DEFAULT_VERIFIER_PATH,
    *,
    now=None,
    expected_uid=None,
):
    _require_private_tty()
    operator_uid = os.geteuid() if expected_uid is None else expected_uid
    path = _require_private_parent(verifier_path, operator_uid)
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise TotpVerificationError("registered TOTP verifier is unsafe") from error
    else:
        raise TotpVerificationError("registered TOTP verifier already exists")

    secret = getpass.getpass("Registered admin TOTP secret: ")
    code = getpass.getpass("Current admin TOTP code: ")
    try:
        if not verify_totp(secret, code, now=now):
            raise TotpVerificationError("registered admin TOTP verification failed")
        verifier = build_registered_secret_verifier(secret)
        write_registered_secret_verifier(
            path,
            verifier,
            expected_uid=operator_uid,
        )
    finally:
        secret = ""
        code = ""


def verify_interactive(
    now=None,
    *,
    verifier_path=DEFAULT_VERIFIER_PATH,
    expected_uid=None,
):
    _require_private_tty()
    operator_uid = os.geteuid() if expected_uid is None else expected_uid
    read_registered_secret_verifier(
        verifier_path,
        expected_uid=operator_uid,
    )

    secret = getpass.getpass("Migration TOTP secret: ")
    code = getpass.getpass("Migration TOTP code: ")
    try:
        verify_and_consume_registered_totp(
            verifier_path,
            secret,
            code,
            now=now,
            expected_uid=operator_uid,
        )
    finally:
        secret = ""
        code = ""


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["enroll", "check"]:
        print(
            "check only; no TOTP secret was read and no verifier file was written"
        )
        print(
            "rerun enroll --apply from the private server terminal to bind the registered admin TOTP credential"
        )
        return 0
    if arguments == ["enroll", "--apply"]:
        action = "enroll"
    elif arguments in ([], ["verify"]):
        action = "verify"
    else:
        print("TOTP secrets and codes must not be supplied as arguments", file=sys.stderr)
        return 2
    try:
        if action == "enroll":
            enroll_interactive()
            print("registered admin TOTP verifier created")
        else:
            verify_interactive()
    except TotpVerificationError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
