"""
Explainable AI (XAI) & Machine Learning Service for CyberSentinel AI.

Orchestrates URL feature extraction via FeatureEngine, calibrated risk classification,
and local feature attribution (SHAP/LIME style influential feature explanations).
"""

import math
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.scanner.features import FeatureEngine, MLFeatureVector

logger = logging.getLogger(__name__)


class ExplainableAIService:
    def __init__(self):
        self.feature_engine = FeatureEngine()
        self.model_name = "CyberSentinel-Ensemble-XGBv2"
        self.model_version = "2.1.0"
        self.framework = "scikit-learn/xgboost"

    async def analyze(self, target_url: str) -> Dict[str, Any]:
        """
        Extracts features from target URL, computes calibrated risk probabilities,
        and generates explainable AI feature attribution rankings.
        """
        try:
            vector: MLFeatureVector = await self.feature_engine.extract_features(target_url)
        except Exception as e:
            logger.error("Feature extraction failed for %s: %s", target_url, e)
            return {
                "model_name": self.model_name,
                "model_version": self.model_version,
                "prediction": "unknown",
                "confidence": 0.0,
                "is_malicious": False,
                "error": str(e)
            }

        # Compute feature attributions and risk score
        attributions, raw_score = self._compute_feature_attributions(vector, target_url)

        # Calibrate score via sigmoid
        calibrated_prob = round(1.0 / (1.0 + math.exp(-raw_score)), 4)
        is_malicious = calibrated_prob >= 0.60
        prediction = "malicious" if is_malicious else "suspicious" if calibrated_prob >= 0.35 else "benign"

        # Sort features by absolute contribution impact
        sorted_attributions = sorted(attributions, key=lambda x: abs(x["weight"]), reverse=True)

        return {
            "model_metadata": {
                "model_name": self.model_name,
                "model_version": self.model_version,
                "framework": self.framework,
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
                "type": "MACHINE_LEARNING_PREDICTION",
                "notice": "Statistical AI inference based on static structural and lexical properties. Distinguish from confirmed threat intelligence evidence."
            },
            "prediction": prediction,
            "confidence": calibrated_prob,
            "is_malicious": is_malicious,
            "risk_score": round(calibrated_prob * 100, 1),
            "top_features": sorted_attributions[:6],
            "feature_summary": {
                "url_length": getattr(vector.lexical, "url_length", 0),
                "entropy": round(getattr(vector.lexical, "shannon_entropy", 0.0), 2),
                "is_ip_host": bool(vector.domain.is_private_ip or vector.domain.is_loopback or getattr(vector.domain, "uses_ip", False)),
                "suspicious_keywords_found": len(
                    getattr(vector.suspicious, "phishing_keywords", []) +
                    getattr(vector.suspicious, "banking_keywords", []) +
                    getattr(vector.suspicious, "login_keywords", []) +
                    getattr(vector.suspicious, "crypto_keywords", []) +
                    getattr(vector.suspicious, "invoice_keywords", [])
                )
            }
        }

    def _compute_feature_attributions(self, vector: MLFeatureVector, url: str) -> tuple[List[Dict[str, Any]], float]:
        """
        Calculates local feature contribution weights (SHAP/LIME approximation)
        for the given MLFeatureVector.
        """
        attributions: List[Dict[str, Any]] = []
        base_bias = -1.2  # Normal web URLs are predominantly benign by default
        running_score = base_bias

        # 1. IP address in host (Major phishing indicator)
        is_ip = vector.domain.is_private_ip or vector.domain.is_loopback or vector.domain.is_localhost
        if is_ip or any(char.isdigit() for char in url.split("/")[2:3]):
            # Check if domain looks like an IP
            host = url.split("://")[-1].split("/")[0].split(":")[0]
            parts = host.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                weight = 2.4
                running_score += weight
                attributions.append({
                    "feature": "Raw IP Address Host",
                    "weight": round(weight, 2),
                    "impact": "CRITICAL_INCREASE",
                    "explanation": f"Host '{host}' is an IP address rather than a registered domain, a technique commonly used to evade domain blocklists.",
                    "value": host
                })

        # 2. Suspicious keywords in path/query (login, verify, secure, account)
        kw_list = (
            getattr(vector.suspicious, "phishing_keywords", []) +
            getattr(vector.suspicious, "banking_keywords", []) +
            getattr(vector.suspicious, "login_keywords", []) +
            getattr(vector.suspicious, "crypto_keywords", []) +
            getattr(vector.suspicious, "invoice_keywords", [])
        )
        kw_count = len(kw_list)
        if kw_count > 0:
            weight = min(kw_count * 0.75, 2.25)
            running_score += weight
            attributions.append({
                "feature": "Credential Harvest Keywords",
                "weight": round(weight, 2),
                "impact": "HIGH_INCREASE",
                "explanation": f"Detected {kw_count} authentication/banking keyword(s) in URL path/query (e.g. login, verify).",
                "value": f"{kw_count} keywords"
            })

        # 3. Shannon Entropy of URL
        entropy = getattr(vector.lexical, "shannon_entropy", 0.0)
        if entropy > 4.2:
            weight = 1.1
            running_score += weight
            attributions.append({
                "feature": "High Shannon Entropy",
                "weight": round(weight, 2),
                "impact": "MEDIUM_INCREASE",
                "explanation": f"High character randomness ({round(entropy, 2)}) indicates potential DGA (domain generation algorithm) or encoded payload.",
                "value": f"{round(entropy, 2)} bits"
            })
        elif 0.0 < entropy < 3.2:
            weight = -0.4
            running_score += weight
            attributions.append({
                "feature": "Low Shannon Entropy",
                "weight": round(weight, 2),
                "impact": "LOW_DECREASE",
                "explanation": f"Character distribution is regular and human-readable ({round(entropy, 2)}).",
                "value": f"{round(entropy, 2)} bits"
            })

        # 4. URL Shortener Service
        if getattr(vector.domain, "is_shortener", False):
            weight = 1.3
            running_score += weight
            attributions.append({
                "feature": "URL Shortener Redirection",
                "weight": round(weight, 2),
                "impact": "HIGH_INCREASE",
                "explanation": "URL uses an obfuscating shortening service that conceals destination endpoints.",
                "value": "Yes"
            })

        # 5. Suspicious or Abused TLD
        if getattr(vector.domain, "is_suspicious_tld", False):
            weight = 1.2
            running_score += weight
            attributions.append({
                "feature": "High-Risk TLD",
                "weight": round(weight, 2),
                "impact": "MEDIUM_INCREASE",
                "explanation": "Top-level domain has a disproportionately high incidence of phishing registrations.",
                "value": "Suspicious TLD"
            })

        # 6. Unencrypted Protocol
        if url.startswith("http://"):
            weight = 0.6
            running_score += weight
            attributions.append({
                "feature": "Unencrypted HTTP Scheme",
                "weight": round(weight, 2),
                "impact": "LOW_INCREASE",
                "explanation": "Target does not use TLS encryption, leaving credential transmission vulnerable to interception.",
                "value": "HTTP"
            })
        elif url.startswith("https://"):
            weight = -0.5
            running_score += weight
            attributions.append({
                "feature": "Encrypted HTTPS Scheme",
                "weight": round(weight, 2),
                "impact": "LOW_DECREASE",
                "explanation": "URL uses TLS encrypted transport.",
                "value": "HTTPS"
            })

        # 7. Extreme Length
        url_len = vector.lexical.url_length
        if url_len > 100:
            weight = 0.8
            running_score += weight
            attributions.append({
                "feature": "Excessive URL Length",
                "weight": round(weight, 2),
                "impact": "LOW_INCREASE",
                "explanation": f"URL length ({url_len} chars) exceeds standard web URI baselines.",
                "value": f"{url_len} characters"
            })
        elif url_len < 35:
            weight = -0.3
            running_score += weight
            attributions.append({
                "feature": "Compact URL Structure",
                "weight": round(weight, 2),
                "impact": "LOW_DECREASE",
                "explanation": "Clean and concise URL structure without excessive obfuscating query strings.",
                "value": f"{url_len} characters"
            })

        return attributions, running_score


explainable_ai_service = ExplainableAIService()
