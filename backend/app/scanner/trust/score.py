"""
Trust Score Calculator for the Trust Intelligence Engine.

This module evaluates already collected trust information and calculates
an overall Trust Score and Trust Level without performing external requests.
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
        Updates the trust_score, trust_level, and reasons in place.

        Args:
            trust_result (TrustResult): The collected trust information.

        Returns:
            TrustResult: The updated TrustResult.
        """
        score = 50.0
        reasons: List[str] = []

        if trust_result.certificate:
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
        trust_result.trust_score = score
        trust_result.reasons = reasons

        # Assign Trust Level
        if score >= 90:
            trust_result.trust_level = TrustLevel.VERY_HIGH
        elif score >= 75:
            trust_result.trust_level = TrustLevel.HIGH
        elif score >= 50:
            trust_result.trust_level = TrustLevel.MEDIUM
        elif score >= 25:
            trust_result.trust_level = TrustLevel.LOW
        else:
            trust_result.trust_level = TrustLevel.VERY_LOW

        return trust_result

    def _score_certificate(self, cert_info: CertificateInfo) -> Tuple[float, List[str]]:
        """
        Evaluate certificate trust signals.
        """
        score_contrib = 0.0
        reasons = []

        if cert_info.trusted_ca:
            score_contrib += 10
            reasons.append("Certificate issued by a trusted CA (+10)")

        if cert_info.expired:
            score_contrib -= 30
            reasons.append("Certificate is expired (-30)")

        if cert_info.self_signed:
            score_contrib -= 20
            reasons.append("Certificate is self-signed (-20)")

        return score_contrib, reasons

    def _score_domain(self, domain_info: DomainInfo) -> Tuple[float, List[str]]:
        """
        Evaluate domain trust signals.
        """
        score_contrib = 0.0
        reasons = []

        if domain_info.domain_age_days is not None:
            if domain_info.domain_age_days > 1825:  # 5 years
                score_contrib += 15
                reasons.append("Domain age is greater than 5 years (+15)")
            elif domain_info.domain_age_days < 30:
                score_contrib -= 25
                reasons.append("Domain is newly registered (less than 30 days) (-25)")

        if domain_info.privacy_protected:
            score_contrib -= 5
            reasons.append("Domain WHOIS is privacy protected (-5)")

        return score_contrib, reasons

    def _score_dns(self, dns_info: DNSInfo) -> Tuple[float, List[str]]:
        """
        Evaluate DNS trust signals.
        """
        score_contrib = 0.0
        reasons = []

        if dns_info.dnssec_enabled:
            score_contrib += 5
            reasons.append("DNSSEC is enabled (+5)")

        if not dns_info.ns_records:
            score_contrib -= 10
            reasons.append("Missing NS records (-10)")

        return score_contrib, reasons

    def _score_reputation(self, rep_info: ReputationInfo) -> Tuple[float, List[str]]:
        """
        Evaluate third-party reputation trust signals.
        """
        score_contrib = 0.0
        reasons = []

        if rep_info.blacklisted:
            score_contrib -= 50
            reasons.append("Domain is blacklisted (-50)")
        else:
            score_contrib += 10
            reasons.append("Domain is not blacklisted (+10)")

        if rep_info.score is not None:
            # Normalize provider score (0-100) into a contribution between -10 and +10
            norm_contrib = (rep_info.score / 5.0) - 10.0
            score_contrib += norm_contrib
            reasons.append(f"Reputation provider score ({rep_info.score}) contributes {norm_contrib:+.1f}")

        return score_contrib, reasons
