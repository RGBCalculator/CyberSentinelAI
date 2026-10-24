import pytest
from app.scanner.trust.certificate import CertificateAnalyzer
from app.scanner.trust.score import TrustScoreCalculator
from app.scanner.trust.schemas import CertificateInfo, DomainInfo, DNSInfo, ReputationInfo, TrustResult


@pytest.mark.asyncio
async def test_badssl_test_target_flagging():
    analyzer = CertificateAnalyzer()
    cert_info = await analyzer.analyze("expired.badssl.com")
    assert cert_info is not None
    assert cert_info.is_badssl_test_target is True
    assert "expired" in cert_info.expected_condition.lower()
    assert cert_info.expired is True


def test_trust_score_calculator_test_target():
    cert = CertificateInfo(
        issuer="BadSSL Untrusted CA",
        subject="expired.badssl.com",
        expired=True,
        self_signed=False,
        is_badssl_test_target=True,
        expected_condition="Deliberately expired certificate"
    )
    domain = DomainInfo(registrar="BadSSL Test Org")
    dns = DNSInfo(a_records=["104.154.89.105"])
    rep = ReputationInfo(blacklisted=False)

    calc = TrustScoreCalculator()
    trust_input = TrustResult(
        certificate=cert,
        domain=domain,
        dns=dns,
        reputation=rep
    )
    result = calc.calculate(trust_input)

    assert result.is_test_case is True
    assert "Deliberately expired certificate" in result.test_case_note
    assert any("TEST CASE" in r for r in result.reasons)


@pytest.mark.asyncio
async def test_neverssl_http_only_characteristics():
    analyzer = CertificateAnalyzer()
    cert_info = await analyzer.analyze("neverssl.com")
    assert cert_info is not None
    assert cert_info.is_badssl_test_target is True
    assert "http-only" in cert_info.expected_condition.lower()
    # neverssl does not enforce HTTPS redirect
    assert cert_info.http_to_https_redirect is False
