#!/usr/bin/env python3
import ipaddress
import pathlib
import re
import sys


MAX_LIST_BYTES = 64 * 1024
MAX_NETWORKS_PER_FAMILY = 128
REAL_IP_LINE = re.compile(r"^set_real_ip_from ([0-9A-Fa-f:.]+/[0-9]+);$")
GEO_LINE = re.compile(r"^    ([0-9A-Fa-f:.]+/[0-9]+) 1;$")


def validate_file(path, expected_family):
    if expected_family not in (4, 6):
        raise ValueError("unsupported IP family")
    raw = pathlib.Path(path).read_bytes()
    if not raw or len(raw) > MAX_LIST_BYTES or b"\r" in raw or b"\x00" in raw:
        raise ValueError("CIDR list has an invalid size or encoding")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("CIDR list must contain ASCII text") from error
    if not lines or len(lines) > MAX_NETWORKS_PER_FAMILY:
        raise ValueError("CIDR list has an invalid network count")

    seen = set()
    for line in lines:
        if not line or line != line.strip():
            raise ValueError("CIDR list contains malformed whitespace")
        try:
            network = ipaddress.ip_network(line, strict=True)
        except ValueError as error:
            raise ValueError("CIDR list contains an invalid network") from error
        if network.version != expected_family or str(network) != line.lower():
            raise ValueError("CIDR list contains a wrong-family or noncanonical network")
        if network in seen:
            raise ValueError("CIDR list contains a duplicate network")
        seen.add(network)
    return len(seen)


def _read_ascii(path):
    raw = pathlib.Path(path).read_bytes()
    if not raw or len(raw) > MAX_LIST_BYTES or b"\r" in raw or b"\x00" in raw:
        raise ValueError("installed Cloudflare boundary file has an invalid size")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("installed Cloudflare boundary file must be ASCII") from error


def _canonical_networks(values, *, allow_loopback=False):
    networks = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise ValueError("installed Cloudflare boundary contains an invalid network") from error
        if str(network) != value.lower():
            raise ValueError("installed Cloudflare boundary contains a noncanonical network")
        if network.is_loopback:
            if not allow_loopback or str(network) not in {"127.0.0.1/32", "::1/128"}:
                raise ValueError("installed Cloudflare boundary contains unexpected loopback scope")
        elif (network.version == 4 and network.prefixlen < 8) or (
            network.version == 6 and network.prefixlen < 20
        ):
            raise ValueError("installed Cloudflare boundary contains an unsafe broad network")
        networks.append(str(network))
    if len(networks) != len(set(networks)):
        raise ValueError("installed Cloudflare boundary contains a duplicate network")
    return set(networks)


def validate_installed_boundary(real_ip_path, geo_path, only_path):
    real_ip = _read_ascii(real_ip_path)
    geo = _read_ascii(geo_path)
    only = _read_ascii(only_path)
    real_values = [
        match.group(1)
        for line in real_ip.splitlines()
        if (match := REAL_IP_LINE.fullmatch(line))
    ]
    geo_values = [
        match.group(1)
        for line in geo.splitlines()
        if (match := GEO_LINE.fullmatch(line))
    ]
    real_networks = _canonical_networks(real_values)
    geo_networks = _canonical_networks(geo_values, allow_loopback=True)
    loopback = {"127.0.0.1/32", "::1/128"}
    if not loopback.issubset(geo_networks) or real_networks != geo_networks - loopback:
        raise ValueError("Cloudflare trust and original-peer networks do not match")
    if sum(ipaddress.ip_network(item).version == 4 for item in real_networks) < 10 \
       or sum(ipaddress.ip_network(item).version == 6 for item in real_networks) < 5:
        raise ValueError("installed Cloudflare boundary has too few networks")
    if real_ip.count("real_ip_header CF-Connecting-IP;") != 1 \
       or real_ip.count("real_ip_recursive on;") != 1:
        raise ValueError("installed real-IP policy is incomplete")
    if (
        only.count("if ($cloudflare_source_allowed = 0)") != 1
        or only.count("return 444;") != 1
        or "$realip_remote_addr" not in only
        or re.search(r"(?m)^(?:allow|deny|set_real_ip_from) ", only)
    ):
        raise ValueError("installed original-peer enforcement policy is invalid")
    return len(real_networks)


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) == 4 and arguments[0] == "--installed":
        validate_installed_boundary(*arguments[1:])
        return 0
    if len(arguments) != 2:
        raise ValueError(
            "usage: validate_cloudflare_cidrs.py IPV4_FILE IPV6_FILE | "
            "--installed REAL_IP_FILE GEO_FILE ONLY_FILE"
        )
    validate_file(arguments[0], 4)
    validate_file(arguments[1], 6)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from None
