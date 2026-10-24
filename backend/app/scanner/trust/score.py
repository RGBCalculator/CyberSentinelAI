"""
Trust Score Calculator for the Trust Intelligence Engine.

This module evaluates already collected trust information and calculates
an overall Trust Score and Trust Level with transparent factor breakdowns.
"""

from typing import Tuple, List

from app.scanner.trust.schemas import (
    TrustResult,
    CertificateInfo,
    DomainInfo,
    DNSInfo,
    ReputationInfo,
    TrustLevel
)


class TrustScoreCalculator:
    """
    Calculator for evaluating trust scores based on collected signals.
    """

    def calculate(self, trust_result: TrustResult) -> TrustResult:
        """
        Calculates the overall trust score and trust level for a given TrustResult.
        Updates the trust_score, trust_level, reasons, and test case notes.
        """
        score = 50.0
        reasons: List[str] = []

        if trust_result.certificate:
            if trust_result.certificate.is_badssl_test_target:
                trust_result.is_test_case = True
                trust_result.test_case_note = (
                    f"Identified as BadSSL Test Target ({trust_result.certificate.expected_condition}). "
                    "These controlled targets demonstrate certificate validation checks and are not assertions of malicious behavior."
                )
                reasons.append(f"CONTROLLED TEST CASE: BadSSL test target ({trust_result.certificate.expected_condition})")

            cert_score, cert_reasons = self._score_certificate(trust_result.certificate)
            score += cert_score
            reasons.extend(cert_reasons)

        if trust_result.domain:
            domain_score, domain_reasons = self._score_domain(trust_result.domain)
            score += domain_score
            reasons.extend(domain_reasons)

        if trust_result.dns:
            dns_score, dns_reasons = self._score_dns(trust_result.dns)
            score += dns_score
            reasons.extend(dns_reasons)

        if trust_result.reputation:
            rep_score, rep_reasons = self._score_reputation(trust_result.reputation)
            score += rep_score
            reasons.extend(rep_reasons)

        # Clamp score between 0 and 100
        score = max(0.0, min(100.0, score))
        trust_result.trust_score = round(score, 1)
        trust_result.reasons = reasons

        # Assign Trust Level
        if score >= 85:
            trust_result.trust_level = TrustLevel.VERY_HIGH
        elif score >= 70:
            trust_result.trust_level = TrustLevel.HIGH
        elif score >= 50:
            trust_result.trust_level = TrustLevel.MEDIUM
        elif score >= 30:
            trust_result.trust_level = TrustLevel.LOW
        else:
            trust_result.trust_level = TrustLevel.VERY_LOW

        return trust_result

    def _score_certificate(self, cert_info: CertificateInfo) -> Tuple[float, List[str]]:
        score_contrib = 0.0
        reasons = []

        if not cert_info.connection_success and cert_info.verification_error:
            score_contrib -= 20
            reasons.append(f"TLS connection failure: {cert_info.verification_error} (-20)")

        if cert_info.trusted_ca:
            score_contrib += 15
            reasons.append("Certificate verified by a trusted Certificate Authority (+15)")
        elif cert_info.connection_success:
            score_contrib -= 15
            reasons.append("Certificate failed root CA trust verification (-15)")

        if cert_info.expired:
            score_contrib -= 30
            reasons.append("Certificate has expired (-30)")

        if cert_info.self_signed:
            score_contrib -= 25
            reasons.append("Certificate is self-signed; lacks trusted third-party authority (-25)")

        if cert_info.hostname_matched is False:
            score_contrib -= 25
            reasons.append("Hostname mismatch: certificate does not cover destination host (-25)")

        if cert_info.http_to_https_redirect is False:
            score_contrib -= 15
            reasons.append("Plain HTTP does not automatically upgrade/redirect to HTTPS (-15)")
        elif cert_info.http_to_https_redirect is True:
            score_contrib += 5
            reasons.append("Plain HTTP securely upgrades/redirects to HTTPS (+5)")

        if cert_info.key_size and cert_info.key_size >= 2048:
            score_contrib += 5
            reasons.append(f"Strong public key length ({cert_info.key_size} bits) (+5)")

        return score_contrib, reasons

    def _score_domain(self, domain_info: DomainInfo) -> Tuple[float, List[str]]:
        score_contrib = 0.0
        reasons = []

        if domain_info.domain_age_days is not None:
            if domain_info.domain_age_days > 1825:  # 5 years
                score_contrib += 15
                reasons.append("Established domain age (>5 years) (+15)")
            elif domain_info.domain_age_days < 30:
                score_contrib -= 25
                reasons.append("Newly registered domain (<30 days) (-25)")
            elif domain_info.domain_age_days < 180:
                score_contrib -= 10
                reasons.append("Relatively young domain (<6 months) (-10)")

        if domain_info.privacy_protected:
            score_contrib -= 5
            reasons.append("Domain WHOIS is privacy protected (-5)")

        return score_contrib, reasons

    def _score_dns(self, dns_info: DNSInfo) -> Tuple[float, List[str]]:
        score_contrib = 0.0
        reasons = []

        if dns_info.dnssec_enabled:
            score_contrib += 10
            reasons.append("DNSSEC cryptographic origin authentication is enabled (+10)")

        if not dns_info.ns_records:
            score_contrib -= 10
            reasons.append("Missing authoritative NS records (-10)")

        if dns_info.mx_records:
            score_contrib += 5
            reasons.append("Configured MX mail exchange records (+5)")

        return score_contrib, reasons

    def _score_reputation(self, rep_info: ReputationInfo) -> Tuple[float, List[str]]:
        score_contrib = 0.0
        reasons = []

        if rep_info.blacklisted:
            score_contrib -= 50
            reasons.append(f"Domain is listed in security blocklist ({rep_info.provider or 'Threat Feed'}) (-50)")
        else:
            score_contrib += 10
            reasons.append("Domain is not observed in active blocklists (+10)")

        if rep_info.score is not None:
            norm_contrib = (rep_info.score / 5.0) - 10.0
            score_contrib += norm_contrib
            reasons.append(f"Reputation confidence ({rep_info.score:.0f}/100) contributes {norm_contrib:+.1f}")

        return score_contrib, reasons
