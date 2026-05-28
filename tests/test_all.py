"""
Test Suite — PhishGuard
Run: python -m pytest tests/ -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'detector'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'simulator'))

import pytest
from email_detector import EmailPhishingDetector, EmailSample
from url_detector   import URLPhishingDetector
from phishing_simulator import PhishingSimulator


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def detector():
    return EmailPhishingDetector()

@pytest.fixture
def url_detector():
    return URLPhishingDetector()

@pytest.fixture
def simulator():
    return PhishingSimulator()


# ── Email Detector Tests ──────────────────────────────────────────────────────

class TestEmailDetector:

    def test_clean_email_not_flagged(self, detector):
        email = EmailSample(
            sender="newsletter@github.com",
            subject="Your weekly digest",
            body="Hi Alice, here are your repositories' updates this week.",
        )
        result = detector.analyze(email)
        assert result.risk_level in ("LOW",)
        assert result.score < 20

    def test_obvious_phish_detected(self, detector):
        email = EmailSample(
            sender="no-reply@paypa1-secure.xyz",
            subject="URGENT: Your account has been SUSPENDED!",
            body=(
                "Dear Customer, verify your account IMMEDIATELY "
                "or it will be closed within 24 hours. "
                "Enter your password and username now."
            ),
            urls=["http://paypal-login.tk/verify"],
            headers={"From": "no-reply@paypa1-secure.xyz", "Reply-To": "evil@steal.ml"},
        )
        result = detector.analyze(email)
        assert result.is_phishing
        assert result.score >= 45
        assert result.risk_level in ("HIGH", "CRITICAL")

    def test_urgency_language_raises_score(self, detector):
        email = EmailSample(
            sender="user@someplace.com",
            subject="Act now or lose your account",
            body="Your account will expire within 24 hours. Verify immediately.",
        )
        result = detector.analyze(email)
        assert result.score > 0

    def test_credential_harvesting_detected(self, detector):
        email = EmailSample(
            sender="support@bank.com",
            subject="Security update",
            body="Please enter your password and username to confirm your identity.",
        )
        result = detector.analyze(email)
        flags_cats = [f["category"] for f in result.flags]
        assert "body" in flags_cats

    def test_mismatched_reply_to_flagged(self, detector):
        email = EmailSample(
            sender="legit@paypal.com",
            subject="Hello",
            body="Normal message.",
            headers={
                "From":     "legit@paypal.com",
                "Reply-To": "attacker@evil.xyz",
            }
        )
        result = detector.analyze(email)
        header_flags = [f for f in result.flags if f["category"] == "header"]
        assert len(header_flags) > 0

    def test_result_serialisable(self, detector):
        import json
        email = EmailSample(sender="a@b.com", subject="Hi", body="Hello!")
        result = detector.analyze(email)
        data = result.to_dict()
        assert json.dumps(data)   # must not raise


# ── URL Detector Tests ────────────────────────────────────────────────────────

class TestURLDetector:

    def test_safe_google_url(self, url_detector):
        r = url_detector.analyze("https://www.google.com/search?q=test")
        assert r.risk_score < 30

    def test_ip_address_url_flagged(self, url_detector):
        r = url_detector.analyze("http://192.168.1.1/bank/login")
        assert r.is_suspicious
        checks = [i["check"] for i in r.indicators]
        assert "ip_address" in checks

    def test_brand_spoof_detected(self, url_detector):
        r = url_detector.analyze("http://paypal-secure-login.xyz/verify")
        assert r.is_suspicious
        checks = [i["check"] for i in r.indicators]
        assert "brand_spoof" in checks

    def test_http_flagged(self, url_detector):
        r = url_detector.analyze("http://randomsite.org/page")
        checks = [i["check"] for i in r.indicators]
        assert "scheme" in checks

    def test_batch_returns_all(self, url_detector):
        urls = ["https://google.com", "http://evil.tk", "https://amazon.com"]
        results = url_detector.batch_analyze(urls)
        assert len(results) == 3

    def test_high_entropy_domain(self, url_detector):
        r = url_detector.analyze("http://xkq8mzpv3nwt.com/login")
        checks = [i["check"] for i in r.indicators]
        assert "entropy" in checks


# ── Simulator Tests ───────────────────────────────────────────────────────────

class TestSimulator:

    def test_list_templates_not_empty(self, simulator):
        templates = simulator.list_templates()
        assert len(templates) >= 4

    def test_generate_returns_simulation(self, simulator):
        result = simulator.generate("account_suspension")
        assert result.sender
        assert result.subject
        assert result.body
        assert result.fake_url
        assert len(result.indicators) > 0

    def test_all_templates_generate(self, simulator):
        for t in simulator.list_templates():
            result = simulator.generate(t["key"])
            assert result.template_name == t["name"]

    def test_custom_brand_used(self, simulator):
        result = simulator.generate("prize_winner", brand="TestBrand")
        assert "TestBrand" in result.body or "testbrand" in result.fake_url.lower()

    def test_disclaimer_included(self, simulator):
        result = simulator.generate("password_reset", include_disclaimer=True)
        assert "SIMULATION" in result.body or "TRAINING" in result.body

    def test_invalid_template_raises(self, simulator):
        with pytest.raises(ValueError):
            simulator.generate("nonexistent_template")


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
