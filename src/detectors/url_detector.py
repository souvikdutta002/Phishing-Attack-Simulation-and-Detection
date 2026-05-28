"""
URL & Website Phishing Detector
Checks URLs for fake/spoofed website indicators without making live HTTP requests.
"""

import re
import math
from dataclasses import dataclass
from typing import List, Dict
from urllib.parse import urlparse, parse_qs


# ── Legitimate Brand List ─────────────────────────────────────────────────────

LEGITIMATE_BRANDS = [
    'paypal', 'amazon', 'google', 'apple', 'microsoft', 'facebook',
    'instagram', 'twitter', 'netflix', 'bank', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'ebay', 'linkedin', 'dropbox',
]

SUSPICIOUS_TLDS = {
    'xyz', 'tk', 'ml', 'ga', 'cf', 'top', 'click', 'download',
    'zip', 'review', 'country', 'stream', 'gq', 'work',
}

SAFE_TLDS = {'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'uk', 'de', 'fr'}


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class URLAnalysis:
    url: str
    is_suspicious: bool
    risk_score: int
    indicators: List[Dict]
    domain: str
    tld: str
    verdict: str

    def to_dict(self):
        return self.__dict__


# ── URL Feature Extractor ─────────────────────────────────────────────────────

class URLPhishingDetector:
    """Stateless URL phishing analyser using structural & lexical features."""

    def analyze(self, url: str) -> URLAnalysis:
        # Normalise
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        parsed    = urlparse(url)
        domain    = parsed.netloc.lower()
        tld       = domain.rsplit('.', 1)[-1] if '.' in domain else ''
        path      = parsed.path
        indicators: List[Dict] = []
        score     = 0

        # Run all checks
        score += self._check_scheme(parsed.scheme, indicators)
        score += self._check_domain_length(domain, indicators)
        score += self._check_suspicious_tld(tld, indicators)
        score += self._check_brand_spoofing(domain, indicators)
        score += self._check_ip_address(domain, indicators)
        score += self._check_subdomain_depth(domain, indicators)
        score += self._check_url_length(url, indicators)
        score += self._check_special_chars(domain, path, indicators)
        score += self._check_entropy(domain, indicators)
        score += self._check_path_keywords(path, indicators)

        is_suspicious = score >= 30
        verdict       = self._verdict(score)

        return URLAnalysis(url, is_suspicious, score, indicators, domain, tld, verdict)

    def batch_analyze(self, urls: List[str]) -> List[URLAnalysis]:
        return [self.analyze(u) for u in urls]

    # ── Individual checks ─────────────────────────────────────────────────────

    def _check_scheme(self, scheme: str, out: List) -> int:
        if scheme == 'http':
            out.append({"check": "scheme", "detail": "HTTP (not HTTPS) — no encryption", "weight": 10})
            return 10
        return 0

    def _check_domain_length(self, domain: str, out: List) -> int:
        if len(domain) > 30:
            out.append({"check": "domain_length", "detail": f"Long domain ({len(domain)} chars)", "weight": 10})
            return 10
        return 0

    def _check_suspicious_tld(self, tld: str, out: List) -> int:
        if tld in SUSPICIOUS_TLDS:
            out.append({"check": "tld", "detail": f"High-risk TLD: .{tld}", "weight": 20})
            return 20
        return 0

    def _check_brand_spoofing(self, domain: str, out: List) -> int:
        for brand in LEGITIMATE_BRANDS:
            if brand in domain:
                # Is it an exact known domain?
                safe = {f'{brand}.com', f'www.{brand}.com', f'{brand}.org', f'{brand}.net'}
                if domain not in safe:
                    out.append({"check": "brand_spoof", "detail": f"Brand name '{brand}' in suspicious domain", "weight": 35})
                    return 35
        return 0

    def _check_ip_address(self, domain: str, out: List) -> int:
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
            out.append({"check": "ip_address", "detail": "Raw IP address used instead of domain name", "weight": 30})
            return 30
        return 0

    def _check_subdomain_depth(self, domain: str, out: List) -> int:
        parts = domain.split('.')
        if len(parts) > 4:
            out.append({"check": "subdomains", "detail": f"Excessive subdomain depth ({len(parts)-2} levels)", "weight": 15})
            return 15
        return 0

    def _check_url_length(self, url: str, out: List) -> int:
        if len(url) > 75:
            out.append({"check": "url_length", "detail": f"Suspiciously long URL ({len(url)} chars)", "weight": 5})
            return 5
        return 0

    def _check_special_chars(self, domain: str, path: str, out: List) -> int:
        score = 0
        if '@' in domain:
            out.append({"check": "at_symbol", "detail": "@ symbol in URL (redirects to different host)", "weight": 25})
            score += 25
        if domain.count('-') > 3:
            out.append({"check": "hyphens", "detail": f"Excessive hyphens in domain ({domain.count('-')})", "weight": 10})
            score += 10
        return score

    def _check_entropy(self, domain: str, out: List) -> int:
        """High Shannon entropy → random-looking domain → likely generated."""
        stripped = domain.split('.')[0]
        entropy = self._shannon_entropy(stripped)
        if entropy > 3.8 and len(stripped) > 8:
            out.append({"check": "entropy", "detail": f"High domain entropy ({entropy:.2f}) — possible DGA", "weight": 15})
            return 15
        return 0

    def _check_path_keywords(self, path: str, out: List) -> int:
        keywords = ['login', 'verify', 'secure', 'update', 'confirm', 'account', 'signin', 'banking']
        found = [k for k in keywords if k in path.lower()]
        if found:
            out.append({"check": "path_keywords", "detail": f"Suspicious path keywords: {', '.join(found)}", "weight": 10})
            return 10
        return 0

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {c: s.count(c) / len(s) for c in set(s)}
        return -sum(p * math.log2(p) for p in freq.values())

    def _verdict(self, score: int) -> str:
        if score >= 70:   return "⛔ PHISHING — Block immediately"
        if score >= 45:   return "🔴 HIGH RISK — Very likely malicious"
        if score >= 30:   return "🟠 MEDIUM RISK — Treat with caution"
        if score >= 15:   return "🟡 LOW RISK — Some suspicious signals"
        return "✅ LIKELY SAFE"


# ── Quick self-test ───────────────────────────────────────────────────────────

if __name__ == '__main__':
    import json
    detector = URLPhishingDetector()

    test_urls = [
        "http://paypal-secure-login.xyz/verify?token=abc",
        "https://www.google.com/search?q=phishing",
        "http://192.168.1.1/banking/login",
        "https://amazon.com.account-update.tk/confirm",
    ]

    for url in test_urls:
        r = detector.analyze(url)
        print(f"\n{'='*60}")
        print(f"URL   : {url}")
        print(f"Score : {r.risk_score}/100")
        print(f"Verdict: {r.verdict}")
        for ind in r.indicators:
            print(f"  ⚠ [{ind['check']}] {ind['detail']}")
