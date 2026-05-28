# 🛡️ PhishGuard — Phishing Attack Simulation & Detection

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-Pytest-brightgreen)](tests/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A modular Python toolkit for **phishing attack simulation** and **multi-layer detection** — built for cybersecurity awareness training and detection research.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Architecture](#architecture)
- [Extending with ML](#extending-with-ml)
- [Skills Learned](#skills-learned)
- [Ethical Use](#ethical-use)
- [Contributing](#contributing)

---

## Overview

PhishGuard consists of three interconnected modules:

| Module | Purpose |
|---|---|
| `EmailPhishingDetector` | Analyses email content, sender, headers & URLs for phishing signals |
| `URLPhishingDetector` | Inspects URLs for structural & lexical phishing characteristics |
| `PhishingSimulator` | Generates realistic phishing email templates for awareness training |
| `EmailFilter` | Routes emails to inbox / review / quarantine based on risk score |

---

## ✨ Features

### Detection
- ✅ Weighted rule-based scoring engine (0–100 risk score)
- ✅ Sender analysis (suspicious TLD, pattern matching)
- ✅ Subject-line urgency & emotional manipulation detection
- ✅ Body scanning — credential harvesting language, generic salutations
- ✅ URL analysis — brand spoofing, IP addresses, entropy, shortened URLs
- ✅ Email header analysis — Reply-To mismatch, missing DKIM
- ✅ Shannon entropy analysis for DGA (Domain Generation Algorithm) domains
- ✅ ML model plug-in interface for sklearn / PyTorch classifiers

### Simulation
- ✅ 4 realistic phishing templates (Account Suspension, Password Reset, Prize Scam, Invoice Fraud)
- ✅ Configurable brand, difficulty, and time pressure
- ✅ Built-in training disclaimers and teaching notes
- ✅ Easy/Medium/Hard difficulty tiers

### Filtering
- ✅ 4-tier routing: Deliver → Review → Quarantine → Block
- ✅ Automatic sender blocklist for CRITICAL threats
- ✅ Human review workflow with notes
- ✅ JSON report export

---

## 🗂️ Project Structure

```
phishing-detector/
├── src/
│   ├── detector/
│   │   ├── email_detector.py      # Core email phishing detector
│   │   └── url_detector.py        # URL / website phishing detector
│   ├── simulator/
│   │   └── phishing_simulator.py  # Phishing email generator
│   └── utils/
│       └── email_filter.py        # Email quarantine & routing
├── tests/
│   └── test_all.py                # Full pytest test suite
├── data/
│   └── samples/                   # Sample phishing emails (JSON)
├── docs/
│   └── architecture.md            # System design notes
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/souvikdutta002/Phishing-Attack-Simulation-and-Detection.git
cd phishing-detector

# Install deps (zero required for the core detector)
pip install -r requirements.txt

# Run the email detector
python src/detector/email_detector.py

# Run the URL detector
python src/detector/url_detector.py

# Run the simulator
python src/simulator/phishing_simulator.py

# Run all tests
pytest tests/ -v
```

---

## 💻 Usage

### 1. Detect Phishing in an Email

```python
from src.detector.email_detector import EmailPhishingDetector, EmailSample

detector = EmailPhishingDetector()

email = EmailSample(
    sender="no-reply@paypa1-secure.xyz",
    subject="URGENT: Your account has been SUSPENDED!",
    body="Dear Customer, verify your account immediately or it will be closed.",
    urls=["http://paypal-login.tk/verify?token=abc123"],
    headers={"Reply-To": "harvest@evil.ml"},
)

result = detector.analyze(email)
print(result.risk_level)    # → CRITICAL
print(result.score)         # → 85
print(result.summary)       # → [CRITICAL] Score 85/100 — 5 indicator(s)...
```

### 2. Analyse a Suspicious URL

```python
from src.detector.url_detector import URLPhishingDetector

url_detector = URLPhishingDetector()
r = url_detector.analyze("http://amazon.com.account-update.tk/confirm")

print(r.verdict)      # → ⛔ PHISHING — Block immediately
print(r.risk_score)   # → 75
for ind in r.indicators:
    print(f"  ⚠ {ind['detail']}")
```

### 3. Generate a Training Simulation

```python
from src.simulator.phishing_simulator import PhishingSimulator

sim = PhishingSimulator()
phish = sim.generate("invoice_fraud", brand="PayPal")

print(phish.subject)
print(phish.body)
print(phish.teaching_notes)
```

### 4. Filter a Batch of Emails

```python
from src.utils.email_filter import EmailFilter
from src.detector.email_detector import EmailSample

f = EmailFilter()
f.process(EmailSample(sender="user@gmail.com", subject="Hello", body="Hi there!"))
f.process(EmailSample(sender="evil@scam.tk",   subject="WIN NOW", body="Click here!"))

print(f.get_stats())
f.export_report("report.json")
```

---

## 🏗️ Architecture

```
Email Input
    │
    ▼
EmailPhishingDetector
    ├── SenderAnalyser      → suspicious domains, TLDs
    ├── SubjectAnalyser     → urgency, CAPS, punctuation
    ├── BodyAnalyser        → credential language, generic greetings
    ├── URLAnalyser         ──► URLPhishingDetector
    │                           ├── SchemeCheck
    │                           ├── BrandSpoofCheck
    │                           ├── EntropyCheck
    │                           └── StructuralChecks
    └── HeaderAnalyser      → Reply-To mismatch, DKIM
         │
         ▼
    Risk Score (0-100)
         │
         ▼
    EmailFilter
    ├── 0–19   → DELIVER
    ├── 20–44  → REVIEW
    ├── 45–69  → QUARANTINE
    └── 70+    → BLOCK
```

---

## 🤖 Extending with ML

The detector is ML-ready. Plug in any sklearn-compatible classifier:

```python
from sklearn.ensemble import RandomForestClassifier
from src.detector.email_detector import EmailPhishingDetector

# Train your model (feature extraction left to you)
clf = RandomForestClassifier()
clf.fit(X_train, y_train)

detector = EmailPhishingDetector()
detector.set_ml_model(clf)   # blended 60% rules / 40% ML
```

Suggested features to extract: TF-IDF on body, URL count, subject length, sender domain age (WHOIS), etc.

---

## 🎓 Skills Learned

By building and studying this project you will gain hands-on experience with:

| Area | Topics |
|---|---|
| **Phishing Techniques** | Social engineering, urgency tactics, brand spoofing, credential harvesting |
| **Email Security** | DKIM, SPF, DMARC, header analysis, sender verification |
| **Detection Systems** | Rule engines, weighted scoring, anomaly detection, ML pipelines |
| **Python Engineering** | Dataclasses, enums, regex, modular architecture, pytest |
| **Threat Modelling** | Risk scoring, triage workflows, quarantine systems |

---

## ⚠️ Ethical Use

> **This tool is for educational and authorized security testing ONLY.**

- 🔒 Only simulate phishing with **explicit written permission** from your organization
- 🚫 Never use this to target individuals without authorization
- 📋 Follow your organization's security policy and applicable laws (CFAA, GDPR, etc.)
- 🎓 Use the simulator output for training, not deception


---
[![](https://visitcount.itsvg.in/api?id=souvikdutta002&icon=0&color=3)](https://visitcount.itsvg.in)


<h2 align="center">✨ Thank You for Visiting My Profile ✨</h2>

<p align="center">
I truly appreciate you taking the time to explore my GitHub profile.<br>
I'm constantly learning and building projects in <b>Cybersecurity, Ethical Hacking, and Software Development</b>.
</p>

<p align="center">
⭐ Consider giving a <b>Star</b> to the repositories you like <br>
🍴 Feel free to <b>Fork</b> and explore the code <br>
🤝 Let's connect and collaborate
</p>

<p align="center">
<img src="https://img.shields.io/badge/Focus-Cybersecurity-blue?style=for-the-badge">
<img src="https://img.shields.io/badge/Learning-Ethical%20Hacking-green?style=for-the-badge">
<img src="https://img.shields.io/badge/Goal-Penetration_Testing-red?style=for-the-badge">
</p>

<p align="center">
<i>*Built for cybersecurity education. Always hack ethically.* 🛡️
</i>
</p>




