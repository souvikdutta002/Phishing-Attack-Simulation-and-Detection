"""
Email Phishing Detector
Analyzes emails for phishing indicators using heuristics + ML-ready pipeline.
"""

import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Tuple
from urllib.parse import urlparse


# ── Phishing Signal Patterns ─────────────────────────────────────────────────

URGENCY_PATTERNS = [
    r'\bact now\b', r'\burgent\b', r'\bimmediate(ly)?\b',
    r'\bexpire[sd]?\b', r'\blimited time\b', r'\bwithin 24 hours\b',
    r'\byour account (will be|has been) (suspended|closed|locked)\b',
    r'\bverify (your|account) (immediately|now|today)\b',
]

CREDENTIAL_PATTERNS = [
    r'\benter (your )?(password|username|login|credentials)\b',
    r'\bconfirm (your )?(account|identity|details)\b',
    r'\bupdate (your )?(billing|payment|credit card)\b',
    r'\bsocial security\b', r'\bSSN\b',
]

SUSPICIOUS_SENDER_PATTERNS = [
    r'no[-_]?reply@(?!(?:amazon|google|microsoft|apple)\.com)',
    r'support@.*\.(xyz|tk|ml|ga|cf|top|click|download)',
    r'@.*-secure\.',
    r'noreply\+[a-z0-9]+@',
]

SUSPICIOUS_URL_PATTERNS = [
    r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r't\.co',  # URL shorteners
    r'@',                                                   # URL with @
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',               # Raw IP addresses
    r'(paypal|amazon|apple|google|microsoft|bank)[^.]*\.(xyz|tk|ml|top)',  # Brand spoofing
]

TRUSTED_DOMAINS = {
    'google.com', 'gmail.com', 'microsoft.com', 'outlook.com',
    'amazon.com', 'apple.com', 'paypal.com', 'github.com',
}


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class EmailSample:
    sender: str
    subject: str
    body: str
    urls: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class DetectionResult:
    is_phishing: bool
    confidence: float          # 0.0 – 1.0
    risk_level: str            # LOW / MEDIUM / HIGH / CRITICAL
    score: int                 # raw points
    flags: List[Dict]          # triggered signals
    summary: str

    def to_dict(self) -> Dict:
        return {
            "is_phishing": self.is_phishing,
            "confidence": round(self.confidence, 3),
            "risk_level": self.risk_level,
            "score": self.score,
            "flags": self.flags,
            "summary": self.summary,
        }


# ── Core Detector ─────────────────────────────────────────────────────────────

class EmailPhishingDetector:
    """
    Rule-based phishing detector with weighted signals.
    Extend by plugging in a trained ML classifier via `set_ml_model()`.
    """

    THRESHOLD_MEDIUM   = 20
    THRESHOLD_HIGH     = 45
    THRESHOLD_CRITICAL = 70

    def __init__(self):
        self._ml_model = None   # placeholder for sklearn / torch model

    def set_ml_model(self, model):
        """Attach a pre-trained classifier (must implement .predict_proba)."""
        self._ml_model = model

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, email: EmailSample) -> DetectionResult:
        flags: List[Dict] = []
        score = 0

        score += self._check_sender(email.sender, flags)
        score += self._check_subject(email.subject, flags)
        score += self._check_body(email.body, flags)
        score += self._check_urls(email.urls, flags)
        score += self._check_headers(email.headers, flags)

        # Optional: blend with ML probability
        if self._ml_model:
            ml_prob = self._get_ml_probability(email)
            score   = int(score * 0.6 + ml_prob * 100 * 0.4)

        confidence  = min(score / 100.0, 1.0)
        risk_level  = self._score_to_risk(score)
        is_phishing = score >= self.THRESHOLD_MEDIUM

        summary = self._build_summary(score, flags, risk_level)
        return DetectionResult(is_phishing, confidence, risk_level, score, flags, summary)

    # ── Signal Checks ─────────────────────────────────────────────────────────

    def _check_sender(self, sender: str, flags: List) -> int:
        score = 0
        sender_lower = sender.lower()

        for pattern in SUSPICIOUS_SENDER_PATTERNS:
            if re.search(pattern, sender_lower, re.IGNORECASE):
                flags.append({"category": "sender", "detail": f"Suspicious sender pattern: {pattern}", "weight": 20})
                score += 20

        domain = self._extract_domain(sender)
        if domain and domain not in TRUSTED_DOMAINS:
            tld = domain.rsplit('.', 1)[-1] if '.' in domain else ''
            if tld in {'xyz', 'tk', 'ml', 'ga', 'cf', 'top', 'click'}:
                flags.append({"category": "sender", "detail": f"Suspicious TLD: .{tld}", "weight": 15})
                score += 15

        return score

    def _check_subject(self, subject: str, flags: List) -> int:
        score = 0
        subject_lower = subject.lower()

        for pattern in URGENCY_PATTERNS:
            if re.search(pattern, subject_lower, re.IGNORECASE):
                flags.append({"category": "subject", "detail": f"Urgency language detected", "weight": 10})
                score += 10
                break

        if re.search(r'[A-Z]{4,}', subject):
            flags.append({"category": "subject", "detail": "Excessive capitalization", "weight": 5})
            score += 5

        if subject.count('!') >= 2:
            flags.append({"category": "subject", "detail": "Multiple exclamation marks", "weight": 5})
            score += 5

        return score

    def _check_body(self, body: str, flags: List) -> int:
        score = 0
        body_lower = body.lower()

        urgency_hits = sum(1 for p in URGENCY_PATTERNS if re.search(p, body_lower, re.IGNORECASE))
        if urgency_hits >= 2:
            flags.append({"category": "body", "detail": f"Multiple urgency phrases ({urgency_hits})", "weight": urgency_hits * 5})
            score += urgency_hits * 5

        for pattern in CREDENTIAL_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                flags.append({"category": "body", "detail": "Credential harvesting language", "weight": 25})
                score += 25
                break

        if re.search(r'dear (customer|user|member|account holder)', body_lower):
            flags.append({"category": "body", "detail": "Generic salutation (no name)", "weight": 10})
            score += 10

        if re.search(r'(grammar|spelling).*error', body_lower) or self._has_spelling_red_flags(body):
            flags.append({"category": "body", "detail": "Poor grammar / spelling indicators", "weight": 8})
            score += 8

        return score

    def _check_urls(self, urls: List[str], flags: List) -> int:
        score = 0
        for url in urls:
            for pattern in SUSPICIOUS_URL_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    flags.append({"category": "url", "detail": f"Suspicious URL pattern: {url[:60]}", "weight": 20})
                    score += 20
                    break

            parsed = urlparse(url)
            if parsed.scheme == 'http' and parsed.netloc not in TRUSTED_DOMAINS:
                flags.append({"category": "url", "detail": f"Unencrypted HTTP link: {url[:60]}", "weight": 10})
                score += 10

        return min(score, 40)   # cap URL score contribution

    def _check_headers(self, headers: Dict, flags: List) -> int:
        score = 0
        if not headers:
            return 0

        reply_to = headers.get('Reply-To', '')
        from_    = headers.get('From', '')
        if reply_to and from_ and self._extract_domain(reply_to) != self._extract_domain(from_):
            flags.append({"category": "header", "detail": "Reply-To domain differs from From domain", "weight": 20})
            score += 20

        if not headers.get('DKIM-Signature'):
            flags.append({"category": "header", "detail": "Missing DKIM signature", "weight": 5})
            score += 5

        return score

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_domain(self, email_addr: str) -> str:
        match = re.search(r'@([\w.-]+)', email_addr)
        return match.group(1).lower() if match else ''

    def _has_spelling_red_flags(self, text: str) -> bool:
        red_flags = ['verfiy', 'acount', 'pasword', 'securty', 'updaet', 'recieve']
        return any(w in text.lower() for w in red_flags)

    def _get_ml_probability(self, email: EmailSample) -> float:
        """Stub: replace with actual feature extraction + model inference."""
        return 0.0

    def _score_to_risk(self, score: int) -> str:
        if score >= self.THRESHOLD_CRITICAL:
            return "CRITICAL"
        if score >= self.THRESHOLD_HIGH:
            return "HIGH"
        if score >= self.THRESHOLD_MEDIUM:
            return "MEDIUM"
        return "LOW"

    def _build_summary(self, score: int, flags: List, risk: str) -> str:
        if not flags:
            return "No phishing indicators detected. Email appears legitimate."
        categories = list({f['category'] for f in flags})
        return (
            f"[{risk}] Score {score}/100 — {len(flags)} indicator(s) across "
            f"{', '.join(categories)}. "
            f"{'Recommend quarantine.' if score >= self.THRESHOLD_HIGH else 'Review advised.'}"
        )


# ── Quick self-test ───────────────────────────────────────────────────────────

if __name__ == '__main__':
    detector = EmailPhishingDetector()

    sample = EmailSample(
        sender="no-reply@paypa1-secure.xyz",
        subject="URGENT: Your account has been SUSPENDED!",
        body=(
            "Dear Customer, \n"
            "We detected suspicious activity. Verify your account IMMEDIATELY "
            "or it will be closed within 24 hours. Click below to confirm your credentials.\n"
            "http://paypal-login.tk/verify?token=abc123"
        ),
        urls=["http://paypal-login.tk/verify?token=abc123"],
        headers={"From": "no-reply@paypa1-secure.xyz", "Reply-To": "collect@evil.ml"},
    )

    result = detector.analyze(sample)
    print(json.dumps(result.to_dict(), indent=2))
