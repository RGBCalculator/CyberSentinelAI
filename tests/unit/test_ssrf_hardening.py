import pytest
from app.security.ssrf import (
    is_safe_target_for_network,
    parse_numeric_ip,
    safe_fetch_url
)


def test_numeric_ip_parsing():
    # Dword / Decimal representation of 127.0.0.1 -> 2130706433
    parsed_dword = parse_numeric_ip("2130706433")
    assert parsed_dword is not None
    assert str(parsed_dword) == "127.0.0.1"

    # Octal
    parsed_octal = parse_numeric_ip("0177.0.0.1")
    assert parsed_octal is not None
    assert str(parsed_octal) == "127.0.0.1"

    # Hex
    parsed_hex = parse_numeric_ip("0x7f.0.0.1")
    assert parsed_hex is not None
    assert str(parsed_hex) == "127.0.0.1"

    # Standard non-numeric host remains None
    assert parse_numeric_ip("example.com") is None


def test_ssrf_dword_ip_blocked():
    is_safe, reason = is_safe_target_for_network("http://2130706433/")
    assert is_safe is False
    assert "restricted" in reason.lower() or "numeric" in reason.lower()


def test_ssrf_hex_ip_blocked():
    is_safe, reason = is_safe_target_for_network("http://0x7f000001/")
    assert is_safe is False
    assert "restricted" in reason.lower() or "numeric" in reason.lower()


def test_ssrf_cloud_metadata_blocked():
    is_safe, reason = is_safe_target_for_network("http://169.254.169.254/latest/meta-data/")
    assert is_safe is False
    assert "metadata" in reason.lower() or "restricted" in reason.lower()


def test_ssrf_ipv6_mapped_ipv4_blocked():
    is_safe, reason = is_safe_target_for_network("http://[::ffff:127.0.0.1]/")
    assert is_safe is False
    assert "restricted" in reason.lower() or "internal" in reason.lower()


def test_ssrf_prohibited_port_blocked():
    is_safe, reason = is_safe_target_for_network("http://example.com:22/")
    assert is_safe is False
    assert "port" in reason.lower()

    is_safe2, reason2 = is_safe_target_for_network("http://example.com:27017/")
    assert is_safe2 is False
    assert "port" in reason2.lower()


def test_ssrf_allowed_valid_public_domain():
    is_safe, reason = is_safe_target_for_network("https://example.com")
    assert is_safe is True
    assert reason is None
