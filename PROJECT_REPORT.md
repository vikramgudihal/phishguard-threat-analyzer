# CYBERSECURITY INTERNSHIP PROJECT REPORT
## Project Title: PhishGuard - Threat Intelligence & Phishing Analysis Engine
**Domain:** Threat Detection, Defensive Engineering & SOC Blue Team Operations  
**Perspective:** Dual-Perspective Architecture (Employee Awareness & SOC Blue Team Forensics)  
**Author:** Cybersecurity Intern  
**Deliverables:** Web SOC Dashboard, CLI Security Tool, Heuristic Engine, Synthetic Corpus, Defanged IoC Harvester, MITRE ATT&CK Taxonomy, Formal Documentation  

---

## 1. Executive Summary

Phishing attacks and credential harvesting campaigns represent the primary initial access vector (`TA0001`) in over 80% of enterprise security compromises worldwide (CISA, Mandiant M-Trends, Verizon DBIR). Modern adversaries continuously evolve their Tactics, Techniques, and Procedures (TTPs)—leveraging homoglyphs, brand typosquatting, raw IP web hosts, and psychological coercion to bypass perimeter email filters.

To address this challenge, I engineered **PhishGuard: Threat Intelligence & Phishing Analysis Engine**.

Developed through the dual perspective of a **Red Team operator** (analyzing how attackers weaponize messages and URLs) and a **SOC Blue Team Analyst** (engineering detection logic, IoC extraction, and containment playbooks), this platform inspects any pasted raw email or link and produces an instant, high-accuracy threat assessment.

### Key Capabilities:
- **Clean Standby State:** On launch, the engine begins clean and empty on standby. Pre-configured scenarios are available via an on-demand dropdown but are never auto-executed on startup.
- **Dual-Perspective User Interface:**
  - *General User View*: Delivers clear, non-technical verdicts, plain-English red flag cards, and actionable safety checklists for employees.
  - *SOC Analyst View*: Exposes full RFC-822 authentication matrices (SPF/DKIM/DMARC), MITRE ATT&CK technique tags, telemetry scoring cards, defanged IoCs, and Blue Team containment playbooks.
- **Real-World Multi-Format Ingestion:** Seamlessly parses full RFC-822 headers, webmail/Outlook pastes, forwarded email blocks, raw unformatted text with embedded links, and direct `.eml` file uploads.
- **MITRE ATT&CK Matrix Correlation:** Every triggered heuristic rule is mapped directly to enterprise techniques (`T1566.002`, `T1656`, `T1586.002`, `T1598`, `T1583.001`, `T1204.001`).
- **Shannon Entropy Analysis:** Detects pseudo-random Domain Generation Algorithms (DGA) and obfuscated session tokens mathematically ($H \ge 3.8$).
- **Defanged Indicators of Compromise (IoC) Harvester:** Extracts target domains, host IPs, and weaponized links into defanged formats (`hxxp://`, `domain[.]com`) with 1-click clipboard copying.
- **Enterprise SOC Console Aesthetic:** High-contrast dark theme (`#0A0E17`), structured telemetry grids, and clean typography (`Inter` & `JetBrains Mono`) designed specifically to avoid AI-generated generic templates.

---

## 2. Threat Actor Tactics vs. Defensive Architecture

The engine counters specific adversarial tradecraft across three primary inspection layers:

```
[Adversary / Red Team Tactic]             [Defensive Detection Engine]
------------------------------------     -----------------------------------------
1. Display Name Impersonation       --->  Cross-references display name against 
   (e.g., "PayPal Security Support")      global brand repository vs actual sender domain.
2. Compromised Relay / Hijacking    --->  Inspects SPF fail/softfail, missing DKIM 
   (e.g., spoofed return-path)            signatures, and DMARC alignment records.
3. Psychological Urgency / Scare    --->  Lexical NLP scans for artificial time compression 
   (e.g., "account suspended in 24h")     and fear appeals to bypass cognitive reasoning.
4. Credential Harvesting Lures      --->  Detects explicit requests for passwords, PINs, 
   (e.g., verify PIN / update card)       banking updates, and sensitive credentials.
5. Deceptive Subdomains / Typos     --->  Levenshtein edit distance, homoglyph replacement 
   (e.g., paypal.com.verify-site.xyz)     (0->o, 1->l), and suspicious TLD evaluation.
6. Direct Numerical IPv4 Hosts      --->  Regex validation flagging raw numerical IP endpoints 
   (e.g., http://192.168.1.105:8080)      used to circumvent domain reputation feeds.
7. Random DGA Generation            --->  Calculates mathematical Shannon Entropy; values 
   (e.g., x7q9z-security.top)             H >= 3.8 flag algorithmic domain generation.
8. HTML Anchor Text Deception       --->  Parses HTML MIME parts to detect mismatches between 
   (e.g., text: paypal.com, href: evil)   visible link text and actual destination URLs.
```

---

## 3. Technology Stack & Implementation

| Layer | Technology | Operational Function |
|:---|:---|:---|
| **Heuristics Core** | Python 3.9+ | High-throughput regex pattern matching, string distance algorithms, and entropy math. |
| **Email Forensics** | Python `email` & `bs4` | RFC-822 header extraction, MIME structure traversal, anchor text verification. |
| **Domain Engine** | `tldextract` & `urllib` | Accurate extraction of apex domains, registered domains, and public suffixes. |
| **Backend REST API**| Flask | Safe local execution with isolated memory buffer (zero network probes). |
| **Web SOC Console** | HTML5 / Vanilla CSS / JS | Professional SOC console with dual-perspective toggle, live statistics, and IoC exports. |
| **CLI Suite** | Python `argparse` | Scriptable automation for batch corpus processing and headless CI/CD evaluation. |

---

## 4. Synthetic Corpus Validation Results

To ensure rigor and eliminate false positives, the engine was benchmarked against a synthetic corpus of authentic legitimate emails and weaponized attack vectors:

| Corpus Scenario Artifact | Category | Final Score | Risk Tier | MITRE TTPs | Findings |
|:---|:---|:---:|:---:|:---:|:---:|
| `legitimate_amazon_receipt.eml` | Legitimate Transaction | **0 / 100** | **LOW** | 0 | 0 |
| `legitimate_github_security.eml` | Legitimate Alert | **0 / 100** | **LOW** | 0 | 0 |
| `legitimate_newsletter.eml` | Legitimate Bulletin | **0 / 100** | **LOW** | 0 | 0 |
| `phishing_ip_banking.eml` | Direct IP Exploit | **88 / 100** | **CRITICAL** | 4 | 10 |
| `phishing_microsoft_mfa.eml` | Typosquatting / Scare | **73 / 100** | **HIGH** | 4 | 8 |
| `phishing_paypal_urgency.eml` | SPF Spoof & Deceptive Subdomain | **93 / 100** | **CRITICAL** | 5 | 13 |
| `phishing_shortener_crypto.eml` | URL Shortener / BEC | **73 / 100** | **HIGH** | 4 | 7 |

### Verification Findings:
1. **Zero False Positives:** Every legitimate corporate email with valid authentication scored `0/100` (Low Risk).
2. **High Threat Sensitivity:** All four phishing scenarios triggered comprehensive findings across headers, body NLP, and URL vectors, correctly scoring between `73` and `93`.

---

## 5. False Positive Management & Educational Disclaimer

In compliance with industry defensive standards:
> **Operational Disclaimer:** Automated heuristics alone should never trigger destructive network containment. Legitimate automated operational notifications (e.g. CI/CD alerts or billing receipts) may occasionally exhibit urgency or atypical domain routing. SOC analysts must corroborate automated telemetry with out-of-band communication before executing enterprise-wide block actions.

---

## 6. Conclusion & Internship Reflection

Through this project, I gained practical hands-on experience in:
- Deconstructing real-world adversary email campaigns and understanding how threat actors evade automated secure email gateways.
- Engineering robust, deterministic heuristic detection rules based on RFC standards (RFC 5322, RFC 7208, RFC 6376, RFC 7489).
- Architecting a dual-perspective cybersecurity product that bridges the gap between high-level employee awareness and deep technical SOC blue-team incident response.
- Implementing safe, static analysis pipelines that execute with zero network overhead or vulnerability risks.
