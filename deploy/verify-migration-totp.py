#!/usr/bin/env python3
import base64
import binascii
import getpass
import hashlib
import hmac
import re
import sys
import time


TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1
BASE32_PATTERN = re.compile(r"^[A-Z2-7]+$")


class TotpVerificationError(Exception):
    pass


def decode_base32_secret(secret):
    normalized = "".join(str(secret or "").split()).upper().rstrip("=")
    if not normalized or not BASE32_PATTERN.fullmatch(normalized):
        raise ValueError("invalid base32 secret")
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    try:
        decoded = base64.b32decode(normalized + padding, casefold=False)
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid base32 secret") from error
    if not decoded:
        raise ValueError("invalid base32 secret")
    return decoded


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


def verify_totp(secret, code, now=None, window=TOTP_WINDOW):
    supplied = str(code or "")
    if not supplied.isascii() or not supplied.isdigit() or len(supplied) != TOTP_DIGITS:
        return False
    if not isinstance(window, int) or window < 0 or window > TOTP_WINDOW:
        return False
    current_time = time.time() if now is None else float(now)
    matched = False
    try:
        for offset in range(-window, window + 1):
            candidate = totp(secret, current_time + offset * TOTP_PERIOD_SECONDS)
            matched = hmac.compare_digest(candidate, supplied) or matched
    except (TypeError, ValueError, OverflowError):
        return False
    return matched


def verify_interactive(now=None):
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise TotpVerificationError("privacy migration TOTP requires an interactive TTY")

    secret = getpass.getpass("Migration TOTP secret: ")
    code = getpass.getpass("Migration TOTP code: ")
    try:
        if not verify_totp(secret, code, now=now):
            raise TotpVerificationError("privacy migration TOTP verification failed")
    finally:
        secret = ""
        code = ""


def main(argv=None):
    arguments = sys.argv if argv is None else argv
    if len(arguments) != 1:
        print("TOTP secrets and codes must not be supplied as arguments", file=sys.stderr)
        return 2
    try:
        verify_interactive()
    except TotpVerificationError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
