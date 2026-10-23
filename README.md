# PhishGuard: Threat Intelligence & Phishing Analysis Engine

An enterprise-grade, multi-vector threat detection platform and dual-perspective security console developed for modern **Cybersecurity Incident Response & Phishing Awareness**. Built with the operational perspective of a **SOC Blue Team Analyst** defending against adversarial **Red Team Phishing Tradecraft & TTPs**.

---

## 📌 Task 2 Deliverables & Requirements Compliance Matrix

This project was built strictly adhering to the **Task 2: Phishing Awareness Analyzer (Threat Detection & Heuristics)** specifications:

| Requirement / Deliverable | Status | Implementation Details & Artifact References |
|:---|:---:|:---|
| **Email Header Inspection** | ✅ **COMPLETE** | Analyzes SPF/DKIM/DMARC status, Sender vs. Return-Path alignment, and Brand Display Name spoofing ([analyzer/email_analyzer.py](file:///c:/Users/vikra/OneDrive/Documents/cyber%20security%20internship/task2/analyzer/email_analyzer.py)). |
| **Body Text Analysis** | ✅ **COMPLETE** | NLP and regex heuristics scanning for artificial urgency, fake security breach warnings, credential requests, and anchor text mismatches ([analyzer/email_analyzer.py](file:///c:/Users/vikra/OneDrive/Documents/cyber%20security%20internship/task2/analyzer/email_analyzer.py)). |
| **URL & Host Analysis** | ✅ **COMPLETE** | Identifies deceptive subdomains, raw IP endpoints, typosquatting (Levenshtein $\le 2$), homoglyphs, and Shannon entropy ($H \ge 3.8$) ([analyzer/url_analyzer.py](file:///c:/Users/vikra/OneDrive/Documents/cyber%20security%20internship/task2/analyzer/url_analyzer.py)). |
| **Risk Score Calculation (0-100)** | ✅ **COMPLETE** | Normalized multi-vector scoring engine with 4 risk tiers (Low, Medium, High, Critical) ([analyzer/heuristics.py](file:///c:/Users/vikra/OneDrive/Documents/cyber%20security%20internship/task2/analyzer/heuristics.py)). |
| **Educational Explanations** | ✅ **COMPLETE** | Dual-perspective output: Plain-English explanations and actionable safety checklists for non-technical users ([cli.py](file:///c:/Users/vikra/OneDrive/Documents/cyber%20security%20internship/task2/cli.py) & Web Console). |
| **Explicit False-Positive Disclaimer** | ✅ **COMPLETE** | Prominently displayed in documentation, Web UI, and CLI outputs explaining heuristic limitations ([README.md](file:///c:/Users/vikra/OneDrive/Documents/cyber%20security%20internship/task2/README.md#7-operational--educational-disclaimer)). |
| **Email / URL Analyzer Script** | ✅ **COMPLETE** | Full CLI analyzer script ([cli.py](file:///c:/Users/vikra/OneDrive/Documents/cyber%20security%20internship/task2/cli.py)) supporting `--file`, `--url`, `--run-corpus`, and `--json`, plus full interactive Web Console ([app.py](file:///c:/Users/vikra/OneDrive/Documents/cyber%20security%20internship/task2/app.py)). |
| **Synthetic Test Corpus** | ✅ **COMPLETE** | Curated corpus with 3 legitimate and 4 synthetic weaponized scenarios in [`samples/`](file:///c:/Users/vikra/OneDrive/Documents/cyber%20security%20internship/task2/samples). |
| **Safe Execution (Zero Network Probes)** | ✅ **COMPLETE** | Strictly deterministic static analysis: zero live network requests, zero web probing, zero credential harvesting. |

---

## 1. Executive Architecture

PhishGuard deconstructs email and URL threats across three foundational vectors with **zero active network probes** (safe, deterministic static heuristics):

```
                        +------------------------------------+
                        | Raw Email Stream / URL Ingestion   |
                        +-----------------+------------------+
                                          |
                 +------------------------+------------------------+
                 |                                                 |
                 v                                                 v
    +--------------------------+                      +--------------------------+
    |  Header Forensics        |                      |  URL & Endpoint Engine   |
    |  - SPF / DKIM / DMARC    |                      |  - Shannon Entropy (DGA) |
    |  - Brand Display Spoof   |                      |  - Numerical IPv4 Hosts  |
    |  - Envelope Alignment    |                      |  - Typosquatting / IDN   |
    +------------+-------------+                      +------------+-------------+
                 |                                                 |
                 +------------------------+------------------------+
                                          |
                                          v
                             +--------------------------+
                             |  Body Psycholinguistics  |
                             |  - Artificial Urgency    |
                             |  - Fear / Breach Lures   |
                             |  - Credential Exfil Cues |
                             |  - BEC / Wire Fraud      |
                             |  - Anchor Text Mismatch  |
                             +------------+-------------+
                                          |
                                          v
                    +---------------------------------------------+
                    |        Threat Intelligence Engine           |
                    |  - Calibrated Composite Risk Score (0-100)  |
                    |  - MITRE ATT&CK TTP Correlation             |
                    |  - Defanged IoC Extraction (RFC standard)   |
                    |  - Blue Team Containment Playbook Actions   |
                    +---------------------------------------------+
                                          |
                    +---------------------+---------------------+
                    |                                           |
                    v                                           v
       [General User Safety View]                 [SOC Analyst Forensic View]
       - Plain-English Verdict                    - Deep Telemetry Metrics
       - Key Red Flags Identified                 - RFC-822 Alignment Matrix
       - Actionable Safety Checklist              - MITRE ATT&CK Matrix Badges
       - Inspected Links Table                    - Defanged IoCs & IR Playbook
```

---

## 2. Adversarial Red Team Tactic Detection Matrix

| Attacker Tactic (Red Team) | MITRE ATT&CK Technique | Defensive Detection Mechanism |
|:---|:---:|:---|
| **Spearphishing Link** | `T1566.002` | Insecure HTTP on auth keywords, credential query tokens (`?session=`, `?email=`), URL shorteners. |
| **Brand Impersonation** | `T1656` | Display name mismatch against global enterprise brand directory; deceptive subdomains (`paypal.com.verify.xyz`). |
| **Lookalike Domains** | `T1583.001` | Levenshtein distance ($\le 2$), homoglyphic character normalization (`0` $\to$ `o`, `1` $\to$ `l`), suspicious TLDs. |
| **Phishing for Information**| `T1598` | Lexical scanning for banking PINs, SSNs, password verification prompts, and urgent deadlines. |
| **Compromised Account / Relay**| `T1586.002` | SPF `fail`/`softfail`, missing or altered DKIM cryptographic signatures, DMARC rejection flags. |
| **DGA & Obfuscation** | `T1566.002` | Shannon Entropy calculation on domain labels ($H \ge 3.8$ flags algorithmic generation). |
| **Executive Fraud / BEC** | `T1656` | Pattern analysis detecting wire transfer lures, gift card requests, and "quick favor / in a meeting" cues. |
| **Anchor Text Deception** | `T1566.002` | HTML parser extracts mismatched hyperlinks where visible display text differs from underlying `href`. |

---

## 3. Risk Scoring & Classification Thresholds

The engine computes a normalized composite score on a `0–100` scale:

$$Score = \min\left(100, \sum W_{headers} + \sum W_{body} + \sum W_{urls}\right)$$

| Score Range | Severity Tier | Visual Indicator | Operational Interpretation |
|:---:|:---:|:---:|:---|
| **0 – 25** | **LOW RISK** | `#10B981` (Green) | Legitimate communication. Conforms to baseline RFC authentication. |
| **26 – 55** | **MEDIUM RISK** | `#F59E0B` (Amber) | Suspicious indicators detected. External sender tagging and verification advised. |
| **56 – 80** | **HIGH RISK** | `#F97316` (Orange) | Active phishing campaign. Gateway quarantine and link block recommended. |
| **81 – 100** | **CRITICAL THREAT** | `#EF4444` (Crimson) | Severe credential theft or weaponized payload. Immediate inbox purge and session revocation. |

### Calibrated Heuristic Weights Breakdown

| Vector | Heuristic Rule Identifier | Points Weight | Threat Indicator & Detection Logic |
|:---|:---|:---:|:---|
| **Headers** | `HEADER_DOMAIN_MISMATCH` | **+35 pts** | Envelope `Return-Path` does not align with `From` domain (RFC 5322 spoofing). |
| **Headers** | `HEADER_DISPLAY_NAME_SPOOF` | **+30 pts** | Display name claims trusted brand (e.g. PayPal) but actual domain differs. |
| **Headers** | `HEADER_SPF_FAIL` / `SOFTFAIL` | **+30 / +18 pts** | SPF authentication record failed or returned softfail (`~all`). |
| **Headers** | `HEADER_DMARC_FAIL` | **+30 pts** | Domain fails DMARC policy validation. |
| **Headers** | `HEADER_DKIM_FAIL` / `MISSING` | **+25 / +12 pts** | Cryptographic DKIM signature missing or signature verification failed. |
| **Headers** | `HEADER_REPLY_TO_MISMATCH` | **+25 pts** | `Reply-To` points to external deceptive address rather than sender domain. |
| **Body NLP** | `BODY_BEC_CEO_FRAUD` | **+35 pts** | Business Email Compromise lures: wire transfer, gift card purchase, "quick favor". |
| **Body NLP** | `BODY_CREDENTIAL_HARVESTING` | **+30 pts** | Direct cues requesting password reset, PIN entry, SSN, or billing update. |
| **Body NLP** | `BODY_SUSPICIOUS_ATTACHMENT_REF` | **+25 pts** | Mentions invoice/statement attachments or executable extensions (.iso, .exe, .scr). |
| **Body NLP** | `BODY_FAKE_SECURITY_ALERT` | **+20 pts** | Manufactured panic: unauthorized logins, account breach, foreign IP alerts. |
| **Body NLP** | `BODY_HIGH_URGENCY` | **+18 pts** | Artificial time compression ("within 24 hours", "immediate action required"). |
| **Body NLP** | `BODY_GENERIC_GREETING` | **+10 pts** | Impersonal greetings ("Dear Customer") common in mass blast campaigns. |
| **URL Engine** | `URL_IP_ADDRESS` | **+40 pts** | Raw numerical IPv4 host used to bypass domain reputation blocklists. |
| **URL Engine** | `URL_TYPOSQUATTING` | **+40 pts** | Levenshtein distance ($\le 2$) or homoglyphs targeting major brand domains. |
| **URL Engine** | `URL_MISLEADING_SUBDOMAIN` | **+35 pts** | Trusted brand placed in subdomain (e.g., `paypal.com.verify-billing.xyz`). |
| **URL Engine** | `URL_PUNYCODE` | **+30 pts** | Internationalized Domain Name (IDN `xn--`) used for visual homograph spoofing. |
| **URL Engine** | `URL_HIGH_ENTROPY` | **+25 pts** | Shannon Entropy $H \ge 3.8$ indicating algorithmic DGA generation. |
| **URL Engine** | `URL_HTTP_FOR_SENSITIVE` | **+25 pts** | Unencrypted plaintext HTTP used on pages with sensitive authentication cues. |
| **URL Engine** | `URL_CREDENTIAL_QUERY_PARAM` | **+25 pts** | Query parameters pre-populating victim emails or auth sessions (`?session=`). |
| **URL Engine** | `URL_SUSPICIOUS_TLD` | **+22 pts** | High-risk TLDs (.xyz, .top, .tk, .click, .buzz, etc.) abused in phishing. |
| **URL Engine** | `URL_SUSPICIOUS_PORT` | **+20 pts** | Non-standard web ports (e.g., `:8080`, `:8443`, `:8888`) hosted on target links. |
| **URL Engine** | `URL_SHORTENER` | **+18 pts** | URL masking services (`bit.ly`, `tinyurl.com`, `t.co`) hiding destination host. |
| **URL Engine** | `URL_EXCESSIVE_SUBDOMAINS` | **+15 pts** | 4+ nested subdomains used to obscure the registered apex domain. |

---

## 4. Dual-Perspective User Interface

PhishGuard provides two tailored perspectives in a single unified interface:

### Perspective A: General User (Phishing Awareness & Education)
- **Plain-English Verdict**: Direct explanation without jargon (e.g. "Do Not Trust This Communication").
- **Key Red Flags**: Intuitive cards explaining why the message was flagged (Urgency Trap, Impersonated Sender, Lookalike Link, Credential Request).
- **Safety Action Checklist**: Concrete steps for non-technical employees (What NOT to do, What TO do).
- **Inspected Links Audit**: Clear breakdown of links and safety status.

### Perspective B: SOC Analyst (Forensic Triage & Blue Team Telemetry)
- **Telemetry Metric Cards**: Header Risk, Body NLP, URL Threat, Flagged Indicators count.
- **RFC-822 Authentication Matrix**: From, Return-Path, Reply-To, SPF, DKIM, DMARC statuses.
- **MITRE ATT&CK Matrix Correlation**: Technique badges with tactics and IDs.
- **Forensic Threat Indicators**: Structured findings table with severity, rule ID, and points weight.
- **Defanged IoC Harvester**: Automatic defanging (`hxxp://`, `example[.]com`, `192[.]168[.]1[.]1`) with 1-click clipboard copy.
- **Incident Response Playbook**: Step-by-step containment instructions.
- **Forensic Export**: One-click JSON report download and Markdown summary copying.

---

## 5. Synthetic Benchmark Corpus

Validated across a corpus of legitimate and adversarial scenarios:

```
Sample File                          | Score  | Risk Level | MITRE TTPs | Flags 
--------------------------------------------------------------------------------
legitimate_amazon_receipt.eml        | 0      | LOW        | 0          | 0     
legitimate_github_security.eml       | 0      | LOW        | 0          | 0     
legitimate_newsletter.eml            | 0      | LOW        | 0          | 0     
phishing_ip_banking.eml              | 88     | CRITICAL   | 4          | 10    
phishing_microsoft_mfa.eml           | 73     | HIGH       | 4          | 8     
phishing_paypal_urgency.eml          | 93     | CRITICAL   | 5          | 13    
phishing_shortener_crypto.eml        | 73     | HIGH       | 4          | 7     
```

---

## 6. Installation & Execution

### Prerequisites
- Python 3.9+
- Dependencies: `pip install -r requirements.txt` (`flask`, `tldextract`, `beautifulsoup4`)

### Run the Web Console
```bash
python app.py
```
Open your browser at `http://127.0.0.1:5000`. On startup, the interface starts completely clean on standby—no pre-loaded samples or auto-runs.

### Run the CLI Tool
```bash
# Analyze a sample email (SOC Analyst perspective)
python cli.py --file samples/phishing_paypal_urgency.eml

# Analyze a sample email (General User perspective)
python cli.py --file samples/phishing_paypal_urgency.eml --audience user

# Scan a standalone URL
python cli.py --url "http://paypal.com.verify-billing.xyz/login"

# Run automated validation across the entire corpus
python cli.py --run-corpus

# Export machine-readable JSON
python cli.py --file samples/phishing_ip_banking.eml --json
```

---

## 7. Operational & Educational Disclaimer

> **DISCLAIMER:** This analyzer operates purely on static heuristic indicators (pattern matching, RFC alignment, and rule weights). False positives are possible: legitimate automated emails (such as bank notifications, server monitors, or password reset alerts) may exhibit urgent wording or domain structures flagged here. Never rely solely on automated heuristics; always verify suspicious communications through verified out-of-band channels. Zero active network probes, web attacks, or credential harvesting are executed by this engine.
