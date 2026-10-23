"""
PhishGuard Threat Intelligence & Heuristics Engine.
Maps real-world attacker Tactics, Techniques, and Procedures (TTPs)
to the MITRE ATT&CK Enterprise Framework with defensive scoring.

Standards: RFC 5322 (Internet Message Format), RFC 7208 (SPF),
RFC 6376 (DKIM), RFC 7489 (DMARC), MITRE ATT&CK v14
"""

import math
import re

# Risk Score Thresholds (0-100 scale)
THRESHOLDS = {
    "LOW": {"max": 25, "label": "LOW RISK (Benign / Verified)", "color": "#10B981"},
    "MEDIUM": {"max": 55, "label": "MEDIUM RISK (Suspicious / Caution)", "color": "#F59E0B"},
    "HIGH": {"max": 80, "label": "HIGH RISK (Likely Phishing Attack)", "color": "#F97316"},
    "CRITICAL": {"max": 100, "label": "CRITICAL THREAT (Severe Phishing / Weaponized)", "color": "#EF4444"}
}

# MITRE ATT&CK Mappings for SOC Triage
MITRE_MAPPINGS = {
    "T1566.002": {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"},
    "T1566.001": {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1598":     {"id": "T1598",     "name": "Phishing for Information", "tactic": "Reconnaissance"},
    "T1656":     {"id": "T1656",     "name": "Impersonation (Brand/Executive)", "tactic": "Defense Evasion"},
    "T1586.002": {"id": "T1586.002", "name": "Compromised Email Account", "tactic": "Resource Development"},
    "T1204.001": {"id": "T1204.001", "name": "Malicious Link Execution", "tactic": "Execution"},
    "T1583.001": {"id": "T1583.001", "name": "Domains: Typosquatting / Lookalike", "tactic": "Resource Development"},
    "T1036.007": {"id": "T1036.007", "name": "Double File Extension / Obfuscation", "tactic": "Defense Evasion"}
}

# High-Value Target Brands Database
HIGH_VALUE_DOMAINS = [
    # Tech & Cloud
    "microsoft.com", "office.com", "office365.com", "google.com", "gmail.com",
    "apple.com", "icloud.com", "amazon.com", "aws.amazon.com", "github.com",
    "dropbox.com", "adobe.com", "zoom.us", "slack.com", "linkedin.com",
    "docusign.net", "docusign.com", "wetransfer.com", "salesforce.com",
    # Financial & Payments
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citigroup.com", "citi.com", "capitalone.com", "stripe.com", "square.com",
    "venmo.com", "coinbase.com", "binance.com", "kraken.com", "meta.com",
    # Shipping & Logistics
    "dhl.com", "fedex.com", "ups.com", "usps.com", "royalmail.com",
    # Telecom & Media
    "netflix.com", "spotify.com", "att.com", "verizon.com"
]

# Suspicious high-risk Top Level Domains
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "buzz", "fit", "rest", "cam", "country", "stream", "kim", "party",
    "date", "racing", "gdn", "icu", "site", "online", "live", "vip",
    "support", "review", "download", "racing", "bid", "loan", "men",
    "tokyo", "accountant", "science", "club", "pw"
}

# Known URL shorteners and masking redirectors
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "shorte.st",
    "bl.ink", "tiny.cc", "s.id", "soo.gd", "tny.im"
}

# High Urgency & Coercive Psychological Keywords
URGENCY_KEYWORDS = [
    r"\bimmediate(ly)? action (is )?required\b",
    r"\bwithin (12|24|48) hours\b",
    r"\baccount (has been|will be) (suspended|terminated|closed|restricted|locked|frozen)\b",
    r"\burgent attention (required|needed)\b",
    r"\bact now or\b",
    r"\blimited time offer\b",
    r"\bfinal notice\b",
    r"\bfailure to (respond|verify|comply)\b",
    r"\byour account has been restricted\b",
    r"\bsuspend(ed)? your access\b",
    r"\bcomplete this before it expires\b",
    r"\btake action now\b",
    r"\bwarning: final reminder\b",
    r"\baccess will be revoked\b"
]

# Security Alert / Fear Inducement Keywords
SECURITY_ALERT_KEYWORDS = [
    r"\bunauthorized (login|access|sign-in|activity)\b",
    r"\bsuspicious (sign-in|activity|transaction|attempt)\b",
    r"\bunusual sign-in activity\b",
    r"\bsecurity compromise\b",
    r"\bsecurity alert\b",
    r"\baccount breach\b",
    r"\bmalicious attempt detected\b",
    r"\byour (pc|mac|device) is infected\b",
    r"\bunrecognized device\b",
    r"\bforeign ip address\b",
    r"\brisk of data loss\b"
]

# Credential Harvesting & Financial Exfiltration Cues
CREDENTIAL_KEYWORDS = [
    r"\bverify your (password|credentials|account|identity|email|details)\b",
    r"\bconfirm your (password|pin|security questions|identity|ssn)\b",
    r"\bupdate your (billing|payment|credit card|banking|direct deposit) (details|info|information)\b",
    r"\benter your (ssn|social security|passcode|otp|one-time code)\b",
    r"\breset your password now\b",
    r"\bclick (here|the link below|this button) to (verify|confirm|unlock|restore)\b",
    r"\bvalidate your (login|identity)\b",
    r"\bclaim your (refund|prize|settlement|compensation)\b",
    r"\bverify billing credentials\b"
]

# Business Email Compromise (BEC) & Executive / CEO Fraud Cues
BEC_KEYWORDS = [
    r"\bare you (at your desk|available right now|in the office)\b",
    r"\bi need a quick favor\b",
    r"\bi am in a meeting\b",
    r"\bwire transfer\b",
    r"\bpurchase (apple|google play|amazon|steam) gift cards\b",
    r"\bdo not call me\b",
    r"\bkeep this confidential\b",
    r"\boverdue invoice\b",
    r"\bpayment remittance advice\b",
    r"\bchange in banking details\b",
    r"\bpayroll update\b"
]

# Generic Salutations (Blast Phishing)
GENERIC_GREETINGS = [
    r"^dear (customer|user|client|member|account holder|subscriber|valued customer|friend)\b",
    r"^hello (customer|user|client|member|account holder)\b",
    r"^attention:? (account holder|customer|user)\b",
    r"^undisclosed recipients\b"
]

# Calibrated Scoring Weights
WEIGHTS = {
    # Header Rules
    "HEADER_SPF_FAIL": 30,
    "HEADER_SPF_SOFTFAIL": 18,
    "HEADER_SPF_NONE": 10,
    "HEADER_DKIM_FAIL": 25,
    "HEADER_DKIM_MISSING": 12,
    "HEADER_DMARC_FAIL": 30,
    "HEADER_DOMAIN_MISMATCH": 35,
    "HEADER_DISPLAY_NAME_SPOOF": 30,
    "HEADER_REPLY_TO_MISMATCH": 25,

    # Body Rules
    "BODY_HIGH_URGENCY": 18,
    "BODY_FAKE_SECURITY_ALERT": 20,
    "BODY_CREDENTIAL_HARVESTING": 30,
    "BODY_BEC_CEO_FRAUD": 35,
    "BODY_GENERIC_GREETING": 10,
    "BODY_SUSPICIOUS_ATTACHMENT_REF": 25,

    # URL Rules
    "URL_IP_ADDRESS": 40,
    "URL_MISLEADING_SUBDOMAIN": 35,
    "URL_TYPOSQUATTING": 40,
    "URL_HIGH_ENTROPY": 25,
    "URL_SUSPICIOUS_TLD": 22,
    "URL_SHORTENER": 18,
    "URL_EXCESSIVE_SUBDOMAINS": 15,
    "URL_PUNYCODE": 30,
    "URL_HTTP_FOR_SENSITIVE": 25,
    "URL_SUSPICIOUS_PORT": 20,
    "URL_CREDENTIAL_QUERY_PARAM": 25
}

# Educational & False-Positive Disclaimer
FALSE_POSITIVE_DISCLAIMER = (
    "SECURITY OPERATIONAL ADVISORY & DISCLAIMER: This analyzer operates strictly on static heuristic indicators, "
    "lexical threat patterns, and MITRE ATT&CK TTP correlation. False positives are possible: legitimate automated "
    "notifications (such as automated CI/CD alerts, billing receipts, or password reset confirmations) may occasionally "
    "exhibit urgent phrasing or atypical domain configurations. Security personnel should corroborate automated findings "
    "via out-of-band communication before executing enterprise-wide containment actions."
)


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes Shannon Entropy of a string to detect randomized Domain Generation
    Algorithms (DGA) or obfuscated parameter payloads.
    Values >= 3.8 for domain labels strongly indicate algorithmic randomness.
    """
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def defang_url(url: str) -> str:
    """Safely defangs URLs to prevent accidental clicks in security tickets/SIEM."""
    if not url:
        return ""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Defang dots in domain part
    return defanged.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    """Defangs a domain name: example.com -> example[.]com"""
    if not domain:
        return ""
    return domain.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    """Defangs an IP address: 192.168.1.1 -> 192[.]168[.]1[.]1"""
    if not ip:
        return ""
    return ip.replace(".", "[.]")
