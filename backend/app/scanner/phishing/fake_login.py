"""
Fake Login Page & Phishing Detection Engine for CyberSentinel AI.

Safely analyzes page structure, DOM elements, brand impersonation signals,
and credential-harvesting patterns in HTML without executing hostile scripts
or interacting with real authentication forms.
"""

import logging
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

from app.security.ssrf import is_safe_target_for_network, safe_fetch_url

logger = logging.getLogger(__name__)

# Common high-value brands frequently targeted by credential phishing
KNOWN_BRANDS = {
    "microsoft": ["microsoft.com", "live.com", "office.com", "office365.com", "login.microsoftonline.com", "outlook.com"],
    "google": ["google.com", "accounts.google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com", "appleid.apple.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "meta.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "adobe": ["adobe.com"]
}

# Credential harvesting field names
SENSITIVE_INPUT_NAMES = {
    "password", "passwd", "pwd", "pass", "user_password", "credential",
    "pin", "ssn", "cvv", "cardnumber", "cc_num", "security_code"
}


class FakeLoginPageDetector:
    """
    Modular detector for fake login pages, brand impersonation,
    and credential-harvesting vectors.
    """

    def inspect_page(self, target_url: str, html_content: str) -> Dict[str, Any]:
        """Convenience method accepting target_url first, followed by html_content."""
        return self.analyze_html(html_content, target_url)

    def analyze_html(self, html_content: str, target_url: str) -> Dict[str, Any]:
        """
        Safely parses HTML markup using BeautifulSoup and extracts
        phishing signals and form submission risks.
        """
        try:
            parsed_target = urlparse(target_url)
            target_host = (parsed_target.hostname or "").lower()
        except Exception:
            target_host = ""

        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception as e:
            return {
                "analyzed": False,
                "error": f"Failed to parse HTML markup: {str(e)}",
                "risk_score": 0.0,
                "verdict": "unknown"
            }

        # 1. Inspect forms & password inputs
        forms = soup.find_all("form")
        password_inputs = soup.find_all("input", {"type": re.compile(r"^password$", re.I)})
        has_password_field = len(password_inputs) > 0

        form_findings: List[Dict[str, Any]] = []
        cross_origin_actions = 0
        raw_ip_actions = 0
        insecure_http_actions = 0

        for f in forms:
            action = f.get("action", "").strip()
            method = (f.get("method", "get")).upper()
            action_url = urljoin(target_url, action) if action else target_url
            
            try:
                parsed_action = urlparse(action_url)
                action_host = (parsed_action.hostname or "").lower()
                action_scheme = parsed_action.scheme.lower()
            except Exception:
                action_host = ""
                action_scheme = ""

            is_cross_origin = False
            if action_host and target_host and action_host != target_host:
                # Check if it's merely a subdomain or a completely different domain
                base_target = ".".join(target_host.split(".")[-2:]) if "." in target_host else target_host
                base_action = ".".join(action_host.split(".")[-2:]) if "." in action_host else action_host
                if base_target != base_action:
                    is_cross_origin = True
                    cross_origin_actions += 1

            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", action_host):
                raw_ip_actions += 1

            if action_scheme == "http" and target_url.startswith("https://"):
                insecure_http_actions += 1

            form_findings.append({
                "action": action or "(same page / empty)",
                "method": method,
                "action_host": action_host,
                "is_cross_origin": is_cross_origin,
                "has_password": any(inp in f.find_all("input") for inp in password_inputs)
            })

        # 2. Check for Brand Impersonation
        page_title = (soup.title.string if soup.title and soup.title.string else "").strip()
        body_text = soup.get_text()[:4000].lower()
        title_lower = page_title.lower()

        impersonated_brand: Optional[str] = None
        brand_mismatch_detected = False

        for brand, legitimate_domains in KNOWN_BRANDS.items():
            if brand in title_lower or f"sign in to {brand}" in body_text or f"log in to {brand}" in body_text:
                impersonated_brand = brand
                # Check if the host belongs to legitimate brand domains
                is_legit = any(target_host == d or target_host.endswith("." + d) for d in legitimate_domains)
                if not is_legit:
                    brand_mismatch_detected = True
                    break

        # 3. Detect sensitive harvesting input names
        inputs = soup.find_all("input")
        sensitive_fields_found: List[str] = []
        for inp in inputs:
            name = (inp.get("name") or inp.get("id") or "").lower()
            if any(s in name for s in SENSITIVE_INPUT_NAMES):
                sensitive_fields_found.append(name)

        # 4. Calculate Risk Score and Verdict
        risk_score = 10.0  # Base benign expectation
        reasons: List[str] = []

        if has_password_field:
            risk_score += 15.0
            reasons.append("Password input field detected.")

        if brand_mismatch_detected and impersonated_brand:
            risk_score += 50.0
            reasons.append(f"Brand impersonation alert: Page claims to be '{impersonated_brand.title()}' but is hosted on unrelated domain '{target_host}'.")

        if cross_origin_actions > 0:
            risk_score += 30.0
            reasons.append(f"Cross-origin form submission detected: credentials/inputs are sent to a third-party host.")

        if raw_ip_actions > 0:
            risk_score += 25.0
            reasons.append("Form action submits directly to a raw IP address.")

        if insecure_http_actions > 0:
            risk_score += 20.0
            reasons.append("Insecure transmission: HTTPS page submits form data over unencrypted plain HTTP.")

        if len(sensitive_fields_found) >= 3:
            risk_score += 15.0
            reasons.append(f"Multiple sensitive credential harvesting inputs found ({', '.join(sensitive_fields_found[:4])}).")

        risk_score = max(0.0, min(100.0, risk_score))

        if risk_score >= 70.0:
            verdict = "malicious"
        elif risk_score >= 40.0:
            verdict = "suspicious"
        elif has_password_field:
            verdict = "login_page"
        else:
            verdict = "benign"

        return {
            "analyzed": True,
            "target_url": target_url,
            "target_host": target_host,
            "page_title": page_title,
            "has_login_form": has_password_field or len(forms) > 0,
            "has_password_field": has_password_field,
            "form_count": len(forms),
            "forms": form_findings,
            "brand_impersonation": {
                "detected": brand_mismatch_detected,
                "claimed_brand": impersonated_brand,
                "is_legitimate_host": not brand_mismatch_detected if impersonated_brand else None
            },
            "brand_mismatch": brand_mismatch_detected,
            "impersonated_brand": impersonated_brand,
            "cross_origin_submission": cross_origin_actions > 0,
            "action_is_ip": raw_ip_actions > 0,
            "sensitive_fields": list(set(sensitive_fields_found)),
            "risk_score": round(risk_score, 1),
            "risk_level": "critical" if risk_score >= 70.0 else "warning" if risk_score >= 40.0 else "clean",
            "verdict": verdict,
            "findings": reasons,
            "indicators": reasons,
            "engine": "CyberSentinel-StaticDOM-Inspector/2.0",
            "browser_sandbox": "sandboxed_static_dom"
        }

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Safely fetches target URL using the hardened SSRF firewall and evaluates
        page structure for fake login and credential theft vectors.
        """
        safe, reason = is_safe_target_for_network(url)
        if not safe:
            return {
                "analyzed": False,
                "error": f"SSRF Protection blocked analysis: {reason}",
                "risk_score": 0.0,
                "verdict": "blocked"
            }

        # Safe streamed fetch with 2MB limit and timeout
        fetch_result = safe_fetch_url(url, max_redirects=3, max_bytes=2_097_152, timeout=6.0)
        if not fetch_result.get("success"):
            return {
                "analyzed": False,
                "error": fetch_result.get("error", "Failed to retrieve page content."),
                "status_code": fetch_result.get("status_code"),
                "risk_score": 0.0,
                "verdict": "unreachable"
            }

        html = fetch_result.get("text", "")
        analysis = self.analyze_html(html, fetch_result.get("final_url", url))
        analysis["status_code"] = fetch_result.get("status_code")
        analysis["redirect_chain"] = fetch_result.get("redirect_chain", [])
        return analysis


fake_login_detector = FakeLoginPageDetector()
