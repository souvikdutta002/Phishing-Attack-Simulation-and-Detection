"""
Email Filter & Quarantine System
Routes incoming emails to inbox / review / quarantine based on phishing score.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum

from email_detector import EmailPhishingDetector, EmailSample, DetectionResult


class FilterAction(str, Enum):
    DELIVER   = "deliver"
    REVIEW    = "review"
    QUARANTINE= "quarantine"
    BLOCK     = "block"


@dataclass
class FilteredEmail:
    email_id: str
    timestamp: str
    sender: str
    subject: str
    action: FilterAction
    result: DetectionResult
    reviewed: bool = False
    reviewer_notes: str = ""

    def to_dict(self):
        d = {
            "email_id":      self.email_id,
            "timestamp":     self.timestamp,
            "sender":        self.sender,
            "subject":       self.subject,
            "action":        self.action.value,
            "reviewed":      self.reviewed,
            "reviewer_notes":self.reviewer_notes,
        }
        d.update(self.result.to_dict())
        return d


class EmailFilter:
    """
    Applies phishing detection and routes emails to appropriate queues.

    Queues
    ------
    inbox      — clean mail delivered normally
    review     — medium risk, held for human review
    quarantine — high / critical risk
    blocked    — never delivered (critical + repeated sender)
    """

    def __init__(
        self,
        deliver_threshold:    int = 20,
        review_threshold:     int = 45,
        quarantine_threshold: int = 70,
    ):
        self.detector   = EmailPhishingDetector()
        self.deliver_t  = deliver_threshold
        self.review_t   = review_threshold
        self.quarantine_t = quarantine_threshold

        self._queues: Dict[str, List[FilteredEmail]] = {
            "inbox": [], "review": [], "quarantine": [], "blocked": []
        }
        self._blocked_senders: set = set()
        self._counter = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def process(self, email: EmailSample) -> FilteredEmail:
        self._counter += 1
        email_id = f"MSG-{self._counter:05d}"

        result = self.detector.analyze(email)
        action = self._route(email.sender, result)

        filtered = FilteredEmail(
            email_id  = email_id,
            timestamp = datetime.now().isoformat(),
            sender    = email.sender,
            subject   = email.subject,
            action    = action,
            result    = result,
        )

        self._queues[action.value].append(filtered)

        if result.risk_level == "CRITICAL":
            self._blocked_senders.add(email.sender)

        return filtered

    def get_queue(self, queue: str) -> List[Dict]:
        return [e.to_dict() for e in self._queues.get(queue, [])]

    def get_stats(self) -> Dict:
        total = sum(len(q) for q in self._queues.values())
        return {
            "total_processed": total,
            "inbox":           len(self._queues["inbox"]),
            "review":          len(self._queues["review"]),
            "quarantine":      len(self._queues["quarantine"]),
            "blocked":         len(self._queues["blocked"]),
            "blocked_senders": len(self._blocked_senders),
            "phishing_rate":   (
                round((len(self._queues["quarantine"]) + len(self._queues["blocked"])) / max(total, 1), 3)
            ),
        }

    def mark_reviewed(self, email_id: str, notes: str = "") -> Optional[FilteredEmail]:
        for queue in self._queues.values():
            for email in queue:
                if email.email_id == email_id:
                    email.reviewed = True
                    email.reviewer_notes = notes
                    return email
        return None

    def export_report(self, path: str = "filter_report.json"):
        report = {
            "generated_at": datetime.now().isoformat(),
            "stats":        self.get_stats(),
            "blocked_senders": list(self._blocked_senders),
            "queues": {
                name: self.get_queue(name)
                for name in self._queues
            }
        }
        with open(path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report exported to {path}")

    # ── Routing Logic ─────────────────────────────────────────────────────────

    def _route(self, sender: str, result: DetectionResult) -> FilterAction:
        if sender in self._blocked_senders:
            return FilterAction.BLOCK
        if result.score >= self.quarantine_t:
            return FilterAction.QUARANTINE
        if result.score >= self.review_t:
            return FilterAction.QUARANTINE
        if result.score >= self.deliver_t:
            return FilterAction.REVIEW
        return FilterAction.DELIVER


# ── Demo ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    filter_engine = EmailFilter()

    emails = [
        EmailSample(
            sender="newsletter@legit-company.com",
            subject="Monthly product updates",
            body="Hi John, here's what's new this month...",
        ),
        EmailSample(
            sender="no-reply@paypa1-secure.xyz",
            subject="URGENT: Your account has been SUSPENDED!",
            body="Dear Customer, verify your account immediately or it will be closed.",
            urls=["http://paypal-login.tk/verify"],
            headers={"Reply-To": "harvest@evil.ml"},
        ),
        EmailSample(
            sender="security@apple-id-verify.top",
            subject="Your Apple ID has been locked",
            body="Dear Account Holder, confirm your credentials now.",
            urls=["https://apple-secure.top/confirm"],
        ),
    ]

    print(f"{'─'*60}")
    print(f"{'EMAIL':40} {'ACTION':12} {'SCORE':>6}")
    print(f"{'─'*60}")
    for email in emails:
        r = filter_engine.process(email)
        print(f"{email.subject[:40]:40} {r.action.value:12} {r.result.score:>6}")

    print(f"\nStats: {json.dumps(filter_engine.get_stats(), indent=2)}")
