"""
PhishGuard URL Threat Detection & Heuristics Engine.

Multi-layered static lexical and structural analysis:
1. Shannon Entropy Analysis (Detection of DGA & Obfuscated Token strings)
2. Numerical Hostname / Raw IPv4 Analysis (Evading Domain Blocklists)
3. Deep Domain Hierarchy & Misleading Subdomain Spoofing
4. Typosquatting & Unicode Confusable Homoglyphs (Levenshtein Distance + Substitution)
5. Non-Standard Port Inspection & Insecure Transport on Sensitive Endpoints
6. Credential Harvesting Query Parameter Inspection (Base64 / Email parameters)
7. Safe Static Verification (Zero active network probes or external exploitation)
"""

import re
from urllib.parse import urlparse, parse_qs
import tldextract

from analyzer.heuristics import (
    HIGH_VALUE_DOMAINS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    WEIGHTS,
    MITRE_MAPPINGS,
    calculate_shannon_entropy,
    defang_url,
    defang_domain,
    defang_ip
)

IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")

# Visual homoglyph substitution dictionary
HOMOGLYPH_SUBS = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '5': 's',
    '8': 'b',
    'vv': 'w',
    'rn': 'm',
    'cl': 'd',
    'q': 'g'
}

STANDARD_PORTS = {80, 443}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes exact edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_substitutions(domain: str) -> str:
    """Normalizes homoglyphic number-to-letter tricks."""
    norm = domain.lower()
    for num, char in HOMOGLYPH_SUBS.items():
        norm = norm.replace(num, char)
    return norm


def check_typosquatting(domain_name: str):
    """
    Evaluates whether registered domain maliciously targets any known enterprise brand.
    """
    domain_clean = domain_name.lower().strip()
    parts = domain_clean.split('.')
    main_label = parts[0] if parts else domain_clean

    for target in HIGH_VALUE_DOMAINS:
        target_label = target.split('.')[0]

        # Exact legitimate match
        if domain_clean == target:
            return None

        # Homoglyph character substitution (e.g. micros0ft vs microsoft, paypa1 vs paypal)
        normalized_label = normalize_substitutions(main_label)
        if normalized_label == target_label and main_label != target_label:
            return {
                "target_brand": target,
                "reason": f"Visual homoglyph spoof of '{target}' using character substitution ('{main_label}')",
                "similarity": "Homoglyph Character Substitution"
            }

        # Edit distance comparison (1 or 2 deletions/insertions/substitutions)
        dist = levenshtein_distance(main_label, target_label)
        if 1 <= dist <= 2 and len(main_label) >= 4 and len(target_label) >= 4:
            return {
                "target_brand": target,
                "reason": f"Typosquatting variation targeting '{target}' (Levenshtein distance: {dist})",
                "similarity": f"Edit Distance: {dist}"
            }

        # Substring prefix/suffix brand mimicry (e.g. paypal-verify or login-microsoft)
        if (f"{target_label}-" in main_label or f"-{target_label}" in main_label or
                f"{target_label}." in domain_clean):
            return {
                "target_brand": target,
                "reason": f"Deceptive brand mimicry: '{main_label}' embeds brand name '{target_label}'",
                "similarity": "Compound Brand Mimicry"
            }

    return None


def analyze_url(url: str) -> dict:
    """
    Performs comprehensive static heuristic threat analysis on a target URL.
    Returns findings with MITRE ATT&CK mappings, score, risk level, and IoCs.
    """
    url_trimmed = url.strip()
    candidate = url_trimmed
    if not (url_trimmed.startswith("http://") or url_trimmed.startswith("https://")):
        candidate = "http://" + url_trimmed

    try:
        parsed = urlparse(candidate)
    except Exception:
        return {
            "url": url,
            "defanged_url": defang_url(url),
            "score": 30,
            "risk_level": "MEDIUM",
            "findings": [{
                "rule": "URL_MALFORMED",
                "points": 30,
                "severity": "MEDIUM",
                "mitre": MITRE_MAPPINGS["T1566.002"],
                "explanation": "Malformed URL failed RFC-3986 syntax validation."
            }],
            "entropy": 0.0,
            "registered_domain": "",
            "defanged_domain": ""
        }

    netloc = parsed.netloc.lower()
    host = netloc.split(":")[0] if ":" in netloc else netloc
    port = parsed.port

    extracted = tldextract.extract(url_trimmed)
    subdomain = extracted.subdomain.lower()
    domain = extracted.domain.lower()
    suffix = extracted.suffix.lower()
    registered_domain = f"{domain}.{suffix}" if suffix else domain

    findings = []
    url_score = 0

    # 1. Direct Numerical IP Hostname
    is_ip = bool(IPV4_REGEX.match(host))
    if is_ip:
        pts = WEIGHTS["URL_IP_ADDRESS"]
        url_score += pts
        findings.append({
            "rule": "URL_IP_ADDRESS",
            "points": pts,
            "severity": "CRITICAL",
            "mitre": MITRE_MAPPINGS["T1566.002"],
            "explanation": f"Host is a raw numerical IPv4 address ({defang_ip(host)}). Threat actors use IP endpoints to evade domain reputation filters."
        })

    # 2. Deceptive Subdomain Spoofing
    if subdomain:
        for target in HIGH_VALUE_DOMAINS:
            target_label = target.split('.')[0]
            if target_label in subdomain and target_label != domain:
                pts = WEIGHTS["URL_MISLEADING_SUBDOMAIN"]
                url_score += pts
                findings.append({
                    "rule": "URL_MISLEADING_SUBDOMAIN",
                    "points": pts,
                    "severity": "HIGH",
                    "mitre": MITRE_MAPPINGS["T1656"],
                    "explanation": f"Subdomain '{subdomain}' mimics trusted brand '{target_label}', disguising true destination '{registered_domain}'."
                })
                break

    # 3. Typosquatting & Brand Spoofing Check
    typo_check = check_typosquatting(registered_domain)
    if typo_check:
        pts = WEIGHTS["URL_TYPOSQUATTING"]
        url_score += pts
        findings.append({
            "rule": "URL_TYPOSQUATTING",
            "points": pts,
            "severity": "CRITICAL",
            "mitre": MITRE_MAPPINGS["T1583.001"],
            "explanation": typo_check["reason"]
        })

    # 4. Shannon Entropy Anomaly (DGA Detection)
    entropy_val = calculate_shannon_entropy(domain)
    if entropy_val >= 3.8 and len(domain) >= 10:
        pts = WEIGHTS["URL_HIGH_ENTROPY"]
        url_score += pts
        findings.append({
            "rule": "URL_HIGH_ENTROPY",
            "points": pts,
            "severity": "HIGH",
            "mitre": MITRE_MAPPINGS["T1566.002"],
            "explanation": f"High lexical randomness detected (Shannon Entropy: {entropy_val}/5.0). Strongly indicative of algorithmic DGA domain generation."
        })

    # 5. High-Risk Top-Level Domain (TLD)
    if suffix in SUSPICIOUS_TLDS:
        pts = WEIGHTS["URL_SUSPICIOUS_TLD"]
        url_score += pts
        findings.append({
            "rule": "URL_SUSPICIOUS_TLD",
            "points": pts,
            "severity": "MEDIUM",
            "mitre": MITRE_MAPPINGS["T1583.001"],
            "explanation": f"Domain registered under high-risk TLD (.{suffix}) frequently observed in automated phishing infrastructure."
        })

    # 6. URL Shortener / Redirection Masking
    if registered_domain in URL_SHORTENERS:
        pts = WEIGHTS["URL_SHORTENER"]
        url_score += pts
        findings.append({
            "rule": "URL_SHORTENER",
            "points": pts,
            "severity": "MEDIUM",
            "mitre": MITRE_MAPPINGS["T1566.002"],
            "explanation": f"URL shortener '{registered_domain}' obscures final landing host, obstructing gateway security inspection."
        })

    # 7. Excessive Subdomain Depth (Mobile Obfuscation)
    subdomain_parts = [p for p in subdomain.split('.') if p]
    if len(subdomain_parts) >= 3:
        pts = WEIGHTS["URL_EXCESSIVE_SUBDOMAINS"]
        url_score += pts
        findings.append({
            "rule": "URL_EXCESSIVE_SUBDOMAINS",
            "points": pts,
            "severity": "MEDIUM",
            "mitre": MITRE_MAPPINGS["T1566.002"],
            "explanation": f"Excessive subdomain depth ({len(subdomain_parts)} levels: '{subdomain}') used to push real domain off mobile viewports."
        })

    # 8. Punycode / IDN Homograph
    if "xn--" in host or "xn--" in parsed.path:
        pts = WEIGHTS["URL_PUNYCODE"]
        url_score += pts
        findings.append({
            "rule": "URL_PUNYCODE",
            "points": pts,
            "severity": "HIGH",
            "mitre": MITRE_MAPPINGS["T1583.001"],
            "explanation": "Punycode ('xn--') detected. Internationalized Domain Names (IDN) disguise non-Latin characters as English letters."
        })

    # 9. Insecure Transport on Sensitive Actions
    path_query = (parsed.path + "?" + parsed.query).lower()
    if parsed.scheme == "http" and any(k in path_query for k in ["login", "signin", "auth", "account", "verify", "secure", "bank", "portal"]):
        pts = WEIGHTS["URL_HTTP_FOR_SENSITIVE"]
        url_score += pts
        findings.append({
            "rule": "URL_HTTP_FOR_SENSITIVE",
            "points": pts,
            "severity": "HIGH",
            "mitre": MITRE_MAPPINGS["T1566.002"],
            "explanation": "Plaintext HTTP transport used for sensitive authentication keywords."
        })

    # 10. Non-Standard Port Anomaly
    if port and port not in STANDARD_PORTS:
        pts = WEIGHTS["URL_SUSPICIOUS_PORT"]
        url_score += pts
        findings.append({
            "rule": "URL_SUSPICIOUS_PORT",
            "points": pts,
            "severity": "MEDIUM",
            "mitre": MITRE_MAPPINGS["T1566.002"],
            "explanation": f"URL binds to abnormal non-standard port ({port}). Attackers host ephemeral kits on non-standard ports."
        })

    # 11. Credential Harvesting Query Parameters
    qs = parse_qs(parsed.query)
    sensitive_params = ["email", "user", "username", "account", "redirect", "token", "session", "goto"]
    matched_params = [p for p in sensitive_params if p in qs]
    if matched_params:
        pts = WEIGHTS["URL_CREDENTIAL_QUERY_PARAM"]
        url_score += pts
        findings.append({
            "rule": "URL_CREDENTIAL_QUERY_PARAM",
            "points": pts,
            "severity": "HIGH",
            "mitre": MITRE_MAPPINGS["T1598"],
            "explanation": f"URL contains pre-populated user parameters ({', '.join(matched_params)}) typical of customized phishing landing pages."
        })

    capped_score = min(url_score, 100)
    if capped_score >= 80:
        level = "CRITICAL"
    elif capped_score >= 56:
        level = "HIGH"
    elif capped_score >= 26:
        level = "MEDIUM"
    else:
        level = "LOW"

    # End-user plain-English verdict
    if capped_score >= 56:
        user_verdict = f"Unsafe / Deceptive Link: This link targets or mimics '{typo_check['target_brand'] if typo_check else registered_domain}' and should not be clicked."
    elif capped_score >= 26:
        user_verdict = f"Suspicious Link: Unusual domain or structure ({registered_domain}). Proceed with caution."
    else:
        user_verdict = f"Standard Link: Normal structure on verified domain ({registered_domain})."

    return {
        "url": url_trimmed,
        "defanged_url": defang_url(url_trimmed),
        "host": host,
        "defanged_host": defang_ip(host) if is_ip else defang_domain(host),
        "is_ip": is_ip,
        "scheme": parsed.scheme or "http",
        "port": port or (443 if parsed.scheme == "https" else 80),
        "registered_domain": registered_domain,
        "defanged_domain": defang_domain(registered_domain),
        "subdomain": subdomain,
        "tld": suffix,
        "entropy": entropy_val,
        "score": capped_score,
        "risk_level": level,
        "user_verdict": user_verdict,
        "findings": findings
    }
