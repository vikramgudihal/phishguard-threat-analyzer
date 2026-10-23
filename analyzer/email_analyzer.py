"""
PhishGuard Email Threat Detection & Heuristic Inspection Engine.

Capabilities:
1. Multi-Format Ingestion:
   - Full RFC-822 headers + MIME bodies
   - Forwarded email blocks & Webmail/Outlook copy-pastes
   - Raw unformatted message bodies & link drops
2. Header Forensics:
   - Display name spoofing against global high-value brands
   - Envelope alignment (From vs Return-Path vs Reply-To)
   - SPF, DKIM, and DMARC cryptographic validation
   - Origin relay IP extraction & hops analysis
3. Body Psychological & Linguistic NLP:
   - High urgency & coercive deadlines
   - Fake security alert & breach scare tactics
   - Direct credential & financial harvesting
   - Business Email Compromise (BEC) & CEO Fraud / Gift card scams
   - Suspicious weaponized attachment references (.exe, .iso, .scr, etc.)
   - HTML Anchor text spoofing / Link mismatch detection
4. URL & Endpoint Correlation:
   - Deep lexical inspection via url_analyzer
5. Dual-Perspective Reporting:
   - General User (Awareness, Plain English, Red Flags, Safety Checklist)
   - SOC Analyst (Forensics, RFC Matrix, MITRE ATT&CK, Defanged IoCs, Blue Team Playbook)
"""

import re
from email import policy
from email.parser import Parser
import tldextract
from bs4 import BeautifulSoup

from analyzer.heuristics import (
    HIGH_VALUE_DOMAINS,
    URGENCY_KEYWORDS,
    SECURITY_ALERT_KEYWORDS,
    CREDENTIAL_KEYWORDS,
    BEC_KEYWORDS,
    GENERIC_GREETINGS,
    WEIGHTS,
    THRESHOLDS,
    MITRE_MAPPINGS,
    FALSE_POSITIVE_DISCLAIMER,
    defang_url,
    defang_domain,
    defang_ip
)
from analyzer.url_analyzer import analyze_url

URL_REGEX = re.compile(r'https?://[^\s<>"\')]+', re.IGNORECASE)

DANGEROUS_EXTENSIONS = [
    r'\.exe\b', r'\.scr\b', r'\.vbs\b', r'\.iso\b', r'\.img\b',
    r'\.bat\b', r'\.cmd\b', r'\.ps1\b', r'\.docm\b', r'\.xlsm\b',
    r'\.pdf\.exe\b', r'\.zip\b', r'\.rar\b', r'\.7z\b', r'\.tar\.gz\b'
]


def extract_domain(email_addr: str) -> str:
    """Extract registered domain from an email address string."""
    if not email_addr or "@" not in email_addr:
        return ""
    domain_part = email_addr.split("@")[-1].strip("<> \t\r\n")
    extracted = tldextract.extract(domain_part)
    return f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain


def parse_flexible_email(raw_input: str):
    """
    Intelligently parses RFC-822 formatted emails, webmail copy-pastes,
    or unstructured body text. Also extracts HTML anchor tags for mismatch detection.
    """
    raw_str = raw_input.strip()
    headers = {}
    body_text = ""
    anchor_mismatches = []

    # Check for RFC-822 header pattern
    has_rfc_headers = bool(re.search(r'^(From|Subject|To|Date|Received):', raw_str, re.MULTILINE | re.IGNORECASE))

    if has_rfc_headers:
        try:
            msg = Parser(policy=policy.default).parsestr(raw_str)
            for k, v in msg.items():
                headers[k] = str(v)

            body_parts = []
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disp = str(part.get("Content-Disposition"))
                    if "attachment" not in content_disp:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            try:
                                text = payload.decode(charset, errors="replace")
                            except Exception:
                                text = str(payload)
                            if content_type == "text/html":
                                soup = BeautifulSoup(text, "html.parser")
                                # Check for anchor text mismatches
                                for a in soup.find_all("a", href=True):
                                    href = a['href'].strip()
                                    display = a.get_text().strip()
                                    if display.startswith("http://") or display.startswith("https://"):
                                        if href != display:
                                            anchor_mismatches.append({"display": display, "href": href})
                                body_parts.append(soup.get_text())
                            else:
                                body_parts.append(text)
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    try:
                        text = payload.decode(charset, errors="replace")
                    except Exception:
                        text = str(payload)
                    if msg.get_content_type() == "text/html":
                        soup = BeautifulSoup(text, "html.parser")
                        for a in soup.find_all("a", href=True):
                            href = a['href'].strip()
                            display = a.get_text().strip()
                            if display.startswith("http://") or display.startswith("https://"):
                                if href != display:
                                    anchor_mismatches.append({"display": display, "href": href})
                        body_parts.append(soup.get_text())
                    else:
                        body_parts.append(text)
                else:
                    body_parts.append(msg.get_payload() or "")

            body_text = "\n".join(body_parts).strip()
            if not body_text:
                body_text = raw_str
        except Exception:
            body_text = raw_str
    else:
        # Check for webmail / forwarded style: "From: ... \n Date: ... \n Subject: ..."
        match_from = re.search(r'(?:From|Sender):\s*([^\r\n]+)', raw_str, re.IGNORECASE)
        match_subj = re.search(r'(?:Subject):\s*([^\r\n]+)', raw_str, re.IGNORECASE)
        match_date = re.search(r'(?:Date):\s*([^\r\n]+)', raw_str, re.IGNORECASE)
        match_to = re.search(r'(?:To):\s*([^\r\n]+)', raw_str, re.IGNORECASE)
        if match_from:
            headers["From"] = match_from.group(1).strip()
        if match_subj:
            headers["Subject"] = match_subj.group(1).strip()
        if match_date:
            headers["Date"] = match_date.group(1).strip()
        if match_to:
            headers["To"] = match_to.group(1).strip()
        body_text = raw_str

    # Extract all embedded URLs
    found_urls = list(set(URL_REGEX.findall(raw_str)))

    return headers, body_text, found_urls, anchor_mismatches


def inspect_headers(headers: dict) -> dict:
    """Evaluates email headers for brand spoofing, alignment, and authentication."""
    findings = []
    score = 0

    from_header = headers.get("From", "")
    return_path = headers.get("Return-Path", "")
    reply_to = headers.get("Reply-To", "")
    auth_results = headers.get("Authentication-Results", "").lower()
    received_spf = headers.get("Received-SPF", "").lower()
    dkim_sig = headers.get("DKIM-Signature", "")

    # Parse display name vs sending email
    match = re.search(r'^(.*?)(?:<([^>]+)>)?$', from_header)
    display_name = ""
    from_email = ""
    if match:
        display_name = (match.group(1) or "").strip().strip('"\'')
        from_email = (match.group(2) or "").strip()
        if not from_email and "@" in display_name:
            from_email = display_name

    from_domain = extract_domain(from_email)
    return_path_domain = extract_domain(return_path)
    reply_to_domain = extract_domain(reply_to)

    # Auth Status Pills
    spf_status = "UNKNOWN"
    dkim_status = "UNKNOWN"
    dmarc_status = "UNKNOWN"

    if not headers or len(headers) < 2:
        return {
            "score": 0,
            "has_headers": False,
            "from": from_header or "Unauthenticated Paste",
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "reply_to_domain": reply_to_domain,
            "display_name": display_name,
            "spf_status": "NONE",
            "dkim_status": "NONE",
            "dmarc_status": "NONE",
            "findings": findings
        }

    # 1. Display Name Impersonation
    if display_name and from_domain:
        for brand_domain in HIGH_VALUE_DOMAINS:
            brand_name = brand_domain.split('.')[0]
            if brand_name in display_name.lower() and from_domain != brand_domain:
                pts = WEIGHTS["HEADER_DISPLAY_NAME_SPOOF"]
                score += pts
                findings.append({
                    "category": "Header Identity",
                    "rule": "HEADER_DISPLAY_NAME_SPOOF",
                    "points": pts,
                    "severity": "CRITICAL",
                    "mitre": MITRE_MAPPINGS["T1656"],
                    "explanation": f"Display name '{display_name}' impersonates trusted brand '{brand_name}', while actual sending domain is '{from_domain}'."
                })
                break

    # 2. Return-Path Mismatch
    if return_path_domain and from_domain and return_path_domain != from_domain:
        pts = WEIGHTS["HEADER_DOMAIN_MISMATCH"]
        score += pts
        findings.append({
            "category": "Header Alignment",
            "rule": "HEADER_DOMAIN_MISMATCH",
            "points": pts,
            "severity": "HIGH",
            "mitre": MITRE_MAPPINGS["T1656"],
            "explanation": f"Envelope Return-Path ('{return_path_domain}') does not align with From domain ('{from_domain}'), indicating bounce spoofing or relay hijacking."
        })

    # 3. Reply-To Mismatch
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        pts = WEIGHTS["HEADER_REPLY_TO_MISMATCH"]
        score += pts
        findings.append({
            "category": "Header Alignment",
            "rule": "HEADER_REPLY_TO_MISMATCH",
            "points": pts,
            "severity": "HIGH",
            "mitre": MITRE_MAPPINGS["T1566.002"],
            "explanation": f"Reply-To domain ('{reply_to_domain}') directs responses away from From domain ('{from_domain}') to an attacker mailbox."
        })

    # 4. SPF Authentication Status
    spf_combined = f"{auth_results} {received_spf}".lower()
    if "spf=fail" in spf_combined or "fail" in received_spf:
        spf_status = "FAIL"
        pts = WEIGHTS["HEADER_SPF_FAIL"]
        score += pts
        findings.append({
            "category": "Email Authentication",
            "rule": "HEADER_SPF_FAIL",
            "points": pts,
            "severity": "CRITICAL",
            "mitre": MITRE_MAPPINGS["T1586.002"],
            "explanation": "Sender Policy Framework (SPF) check failed. The sending mail server IP is unauthorized by the domain's DNS SPF record."
        })
    elif "spf=softfail" in spf_combined or "softfail" in received_spf:
        spf_status = "SOFTFAIL"
        pts = WEIGHTS["HEADER_SPF_SOFTFAIL"]
        score += pts
        findings.append({
            "category": "Email Authentication",
            "rule": "HEADER_SPF_SOFTFAIL",
            "points": pts,
            "severity": "MEDIUM",
            "mitre": MITRE_MAPPINGS["T1586.002"],
            "explanation": "SPF check returned softfail (~all). The sending IP is unverified by the domain owner."
        })
    elif "spf=pass" in spf_combined or "pass" in received_spf:
        spf_status = "PASS"
    else:
        spf_status = "NONE"

    # 5. DKIM Validation Status
    if "dkim=fail" in auth_results:
        dkim_status = "FAIL"
        pts = WEIGHTS["HEADER_DKIM_FAIL"]
        score += pts
        findings.append({
            "category": "Email Authentication",
            "rule": "HEADER_DKIM_FAIL",
            "points": pts,
            "severity": "HIGH",
            "mitre": MITRE_MAPPINGS["T1586.002"],
            "explanation": "DKIM cryptographic signature verification failed. Message headers or payload have been altered in transit."
        })
    elif "dkim=pass" in auth_results or dkim_sig:
        dkim_status = "PASS"
    else:
        dkim_status = "MISSING"

    # 6. DMARC Alignment
    if "dmarc=fail" in auth_results or "dmarc=reject" in auth_results:
        dmarc_status = "FAIL"
        pts = WEIGHTS["HEADER_DMARC_FAIL"]
        score += pts
        findings.append({
            "category": "Email Authentication",
            "rule": "HEADER_DMARC_FAIL",
            "points": pts,
            "severity": "CRITICAL",
            "mitre": MITRE_MAPPINGS["T1656"],
            "explanation": "DMARC policy check failed. Neither SPF nor DKIM aligned with the From header identity."
        })
    elif "dmarc=pass" in auth_results:
        dmarc_status = "PASS"
    else:
        dmarc_status = "NONE"

    return {
        "score": min(score, 100),
        "has_headers": True,
        "from": from_header or "No From Header",
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "reply_to_domain": reply_to_domain,
        "display_name": display_name,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "findings": findings
    }


def inspect_body(body_text: str, anchor_mismatches: list = None) -> dict:
    """Evaluates body copy for psychological manipulation, credential lures, BEC, and file lures."""
    findings = []
    score = 0
    matched = {
        "urgency": [],
        "security": [],
        "credential": [],
        "bec": [],
        "attachments": []
    }

    body_lower = body_text.lower()

    # 1. High Urgency
    for pat in URGENCY_KEYWORDS:
        m = re.findall(pat, body_lower)
        if m:
            matched["urgency"].extend(m if isinstance(m[0], str) else [x[0] for x in m])
    if matched["urgency"]:
        pts = WEIGHTS["BODY_HIGH_URGENCY"]
        score += pts
        sample_txt = ", ".join(list(set(matched["urgency"]))[:3])
        findings.append({
            "category": "Body Manipulation",
            "rule": "BODY_HIGH_URGENCY",
            "points": pts,
            "severity": "MEDIUM",
            "mitre": MITRE_MAPPINGS["T1598"],
            "explanation": f"Artificial panic/urgency phrases detected ({sample_txt}). Attackers compress decision time to prevent scrutiny."
        })

    # 2. Fake Security Alert
    for pat in SECURITY_ALERT_KEYWORDS:
        m = re.findall(pat, body_lower)
        if m:
            matched["security"].extend(m if isinstance(m[0], str) else [x[0] for x in m])
    if matched["security"]:
        pts = WEIGHTS["BODY_FAKE_SECURITY_ALERT"]
        score += pts
        sample_txt = ", ".join(list(set(matched["security"]))[:3])
        findings.append({
            "category": "Body Manipulation",
            "rule": "BODY_FAKE_SECURITY_ALERT",
            "points": pts,
            "severity": "HIGH",
            "mitre": MITRE_MAPPINGS["T1656"],
            "explanation": f"Fabricated incident/security warning cues detected ({sample_txt}). Lures user into executing unauthorized recovery actions."
        })

    # 3. Credential Harvesting Cues
    for pat in CREDENTIAL_KEYWORDS:
        m = re.findall(pat, body_lower)
        if m:
            matched["credential"].extend(m if isinstance(m[0], str) else [x[0] for x in m])
    if matched["credential"]:
        pts = WEIGHTS["BODY_CREDENTIAL_HARVESTING"]
        score += pts
        sample_txt = ", ".join(list(set(matched["credential"]))[:3])
        findings.append({
            "category": "Credential Harvesting",
            "rule": "BODY_CREDENTIAL_HARVESTING",
            "points": pts,
            "severity": "CRITICAL",
            "mitre": MITRE_MAPPINGS["T1598"],
            "explanation": f"Direct prompt requesting credential or billing re-authentication ({sample_txt})."
        })

    # 4. Business Email Compromise (BEC) & Executive Fraud
    for pat in BEC_KEYWORDS:
        m = re.findall(pat, body_lower)
        if m:
            matched["bec"].extend(m if isinstance(m[0], str) else [x[0] for x in m])
    if matched["bec"]:
        pts = WEIGHTS["BODY_BEC_CEO_FRAUD"]
        score += pts
        sample_txt = ", ".join(list(set(matched["bec"]))[:3])
        findings.append({
            "category": "Executive Impersonation (BEC)",
            "rule": "BODY_BEC_CEO_FRAUD",
            "points": pts,
            "severity": "CRITICAL",
            "mitre": MITRE_MAPPINGS["T1656"],
            "explanation": f"Business Email Compromise (BEC) wire transfer or gift card cues detected ({sample_txt})."
        })

    # 5. Weaponized Attachment / Archive Mentions
    for pat in DANGEROUS_EXTENSIONS:
        m = re.findall(pat, body_lower)
        if m:
            matched["attachments"].extend(m)
    if matched["attachments"]:
        pts = WEIGHTS["BODY_SUSPICIOUS_ATTACHMENT_REF"]
        score += pts
        findings.append({
            "category": "Payload Delivery",
            "rule": "BODY_SUSPICIOUS_ATTACHMENT_REF",
            "points": pts,
            "severity": "HIGH",
            "mitre": MITRE_MAPPINGS["T1566.001"],
            "explanation": f"References dangerous executable or container extensions ({', '.join(set(matched['attachments']))})."
        })

    # 6. Generic Salutation Check
    lines = [line.strip().lower() for line in body_text.splitlines() if line.strip()]
    first_few = " ".join(lines[:4])
    for pat in GENERIC_GREETINGS:
        if re.search(pat, first_few):
            pts = WEIGHTS["BODY_GENERIC_GREETING"]
            score += pts
            findings.append({
                "category": "Linguistic Profile",
                "rule": "BODY_GENERIC_GREETING",
                "points": pts,
                "severity": "LOW",
                "mitre": MITRE_MAPPINGS["T1598"],
                "explanation": "Impersonal greeting (e.g. 'Dear Customer'). Legitimate corporate communications typically address the recipient by name."
            })
            break

    # 7. HTML Anchor Text Mismatches (Deceptive Links)
    if anchor_mismatches:
        pts = 35
        score += pts
        findings.append({
            "category": "Deceptive Hyperlinks",
            "rule": "HTML_ANCHOR_MISMATCH",
            "points": pts,
            "severity": "CRITICAL",
            "mitre": MITRE_MAPPINGS["T1566.002"],
            "explanation": f"Anchor text displays one URL ('{anchor_mismatches[0]['display']}') but hyperlink redirects to a completely different destination ('{anchor_mismatches[0]['href']}')."
        })

    return {
        "score": min(score, 100),
        "matched": matched,
        "findings": findings
    }


def generate_general_user_report(score: int, findings: list, urls: list, subject: str, sender: str) -> dict:
    """Generates a plain-English, actionable report designed for non-technical employees."""
    if score >= 80:
        verdict_badge = "CRITICAL PHISHING"
        verdict_color = "#EF4444"
        verdict_heading = "DANGER: High-Risk Phishing Attack Detected"
        verdict_desc = (
            "This communication appears to be a fraudulent phishing attempt designed to steal your credentials, "
            "financial details, or compromise your workstation. Do not trust the sender name or click any links."
        )
    elif score >= 56:
        verdict_badge = "SUSPICIOUS"
        verdict_color = "#F97316"
        verdict_heading = "WARNING: Highly Suspicious Communication"
        verdict_desc = (
            "This message displays significant red flags such as urgent demands, unaligned sender addresses, "
            "or suspicious link destinations. Exercise extreme caution."
        )
    elif score >= 26:
        verdict_badge = "CAUTION ADVISED"
        verdict_color = "#F59E0B"
        verdict_heading = "NOTICE: Proceed with Caution"
        verdict_desc = (
            "The message exhibits some minor anomalies or urgency cues. While it may be an automated notification, "
            "verify the sender through an official channel before taking action."
        )
    else:
        verdict_badge = "VERIFIED SAFE"
        verdict_color = "#10B981"
        verdict_heading = "SAFE: Legitimate Communication Verified"
        verdict_desc = (
            "This communication passes standard security authentication checks. No high-risk manipulation, "
            "spoofing, or deceptive links were identified."
        )

    # Compile Red Flags for End Users
    red_flags = []
    for f in findings:
        cat = f.get("category", "")
        rule = f.get("rule", "")
        sev = f.get("severity", "MEDIUM")

        if "DISPLAY_NAME_SPOOF" in rule:
            red_flags.append({
                "title": "Impersonated Sender Name",
                "severity": "CRITICAL",
                "explanation": "The email claims to be from a well-known brand, but was actually sent from a completely different, unverified email domain."
            })
        elif "DOMAIN_MISMATCH" in rule or "REPLY_TO_MISMATCH" in rule:
            red_flags.append({
                "title": "Hidden Return / Reply Address",
                "severity": "HIGH",
                "explanation": "If you reply to this message, your response goes to a hidden external mailbox instead of the official company address."
            })
        elif "HIGH_URGENCY" in rule:
            red_flags.append({
                "title": "Artificial Panic & Pressure",
                "severity": "MEDIUM",
                "explanation": "The message pressures you with immediate deadlines (e.g. 'within 24 hours' or 'account suspended') to make you panic and click without thinking."
            })
        elif "FAKE_SECURITY_ALERT" in rule:
            red_flags.append({
                "title": "Fake Security Warning",
                "severity": "HIGH",
                "explanation": "Scammers often claim your account was breached or accessed from another country to trick you into clicking their fake recovery link."
            })
        elif "CREDENTIAL_HARVESTING" in rule:
            red_flags.append({
                "title": "Request for Passwords or Banking Details",
                "severity": "CRITICAL",
                "explanation": "The message asks you to verify your password, PIN, or payment details. Legitimate organizations never request your credentials via email links."
            })
        elif "URL_TYPOSQUATTING" in rule:
            red_flags.append({
                "title": "Lookalike / Fake Website Link",
                "severity": "CRITICAL",
                "explanation": "A link in this email points to a fake website spelled almost identically to a trusted brand to deceive you into logging in."
            })
        elif "URL_IP_ADDRESS" in rule:
            red_flags.append({
                "title": "Direct Numbered Link (IP Address)",
                "severity": "CRITICAL",
                "explanation": "A link uses a raw number sequence instead of an official website name, which is a common trick used to bypass security filters."
            })
        elif "URL_MISLEADING_SUBDOMAIN" in rule:
            red_flags.append({
                "title": "Misleading Web Address",
                "severity": "HIGH",
                "explanation": "The link puts a trusted brand name at the start of the address (e.g. paypal.com.something.xyz), but the actual destination is a scam site."
            })
        elif "HTML_ANCHOR_MISMATCH" in rule:
            red_flags.append({
                "title": "Deceptive Click Target",
                "severity": "CRITICAL",
                "explanation": "The visible text of a link says one address, but clicking it takes you somewhere completely different."
            })

    # Recommended Safety Actions
    actions = []
    if score >= 56:
        actions.append("DO NOT click on any links, open attachments, or download files from this message.")
        actions.append("DO NOT reply to the sender or provide passwords, OTP codes, or banking information.")
        actions.append("Use your email client's 'Report Phishing' button or forward this to your Security Operations / IT team.")
        actions.append("If you are concerned about your account, open a browser manually and type the company's official web address yourself.")
    elif score >= 26:
        actions.append("Verify the sender's identity by contacting them through a known, trusted phone number or chat channel.")
        actions.append("Check the actual website address carefully before entering any personal information.")
        actions.append("Avoid clicking links inside unsolicited messages.")
    else:
        actions.append("No immediate threat detected. Normal email safety guidelines apply.")

    # Simplified user links
    user_links = []
    for u in urls:
        user_links.append({
            "url": u["url"],
            "domain": u["registered_domain"],
            "risk_level": u["risk_level"],
            "verdict": u.get("user_verdict", "Evaluated link destination.")
        })

    return {
        "verdict_badge": verdict_badge,
        "verdict_color": verdict_color,
        "verdict_heading": verdict_heading,
        "verdict_desc": verdict_desc,
        "red_flags": red_flags[:6],  # Top red flags
        "safety_actions": actions,
        "user_links": user_links
    }


def generate_soc_playbook(score: int) -> list:
    """Generates standard SOC Blue Team containment and defensive playbook actions."""
    playbook = []
    if score >= 80:
        playbook.append("IMMEDIATE PERIMETER BLOCK: Blacklist sending email domain and origin relay IP on Secure Email Gateways (Proofpoint/Mimecast).")
        playbook.append("TENANT INBOX PURGE: Execute tenant-wide PowerShell purge query (Exchange Online HardDelete / Google Workspace Quarantine).")
        playbook.append("IDENTITY CONTAINMENT: Revoke active session refresh tokens and trigger forced password reset + MFA re-enrollment.")
        playbook.append("EDR TELEMETRY HUNT: Query CrowdStrike/SentinelOne for outbound HTTP/DNS requests to extracted target domains.")
        playbook.append("SIEM ALERT CORRELATION: Correlate recipient mailbox logs for successful authentication events post-delivery.")
    elif score >= 56:
        playbook.append("ADMINISTRATIVE QUARANTINE: Move message to administrative review quarantine; notify targeted recipient.")
        playbook.append("URL PROXY BLOCKLIST: Push extracted malicious URLs to corporate web proxy and perimeter firewalls.")
        playbook.append("PHISHING SIMULATION QUEUE: Route recipient to targeted brand-impersonation training module within LMS.")
    elif score >= 26:
        playbook.append("HEADER TAGGING: Apply external warning banner indicating unverified authentication or urgent sentiment.")
        playbook.append("OUT-OF-BAND VALIDATION: Direct recipient to verify legitimacy with sender via corporate Slack or Teams.")
    else:
        playbook.append("BENIGN BASELINE: Conforms to legitimate corporate messaging standards. Retain standard logging.")
    return playbook


def analyze_email(raw_input: str) -> dict:
    """
    Master Threat Inspection pipeline for emails.
    Produces dual-perspective results: General User Awareness & SOC Forensics.
    """
    headers, body_text, found_urls, anchor_mismatches = parse_flexible_email(raw_input)

    header_res = inspect_headers(headers)
    body_res = inspect_body(body_text, anchor_mismatches)

    url_results = []
    max_url_score = 0
    url_findings = []
    iocs = {
        "domains": set(),
        "ips": set(),
        "urls": set()
    }

    if header_res["from_domain"]:
        iocs["domains"].add(header_res["from_domain"])
    if header_res["return_path_domain"]:
        iocs["domains"].add(header_res["return_path_domain"])

    for u in found_urls:
        u_res = analyze_url(u)
        url_results.append(u_res)
        iocs["urls"].add(u_res["defanged_url"])
        if u_res["registered_domain"]:
            iocs["domains"].add(u_res["defanged_domain"])
        if u_res.get("is_ip") and u_res.get("host"):
            iocs["ips"].add(u_res["defanged_host"])

        if u_res["score"] > max_url_score:
            max_url_score = u_res["score"]

        for f in u_res["findings"]:
            url_findings.append({
                "category": f"URL Infrastructure ({u_res['registered_domain']})",
                "rule": f["rule"],
                "points": f["points"],
                "severity": f["severity"],
                "mitre": f.get("mitre", MITRE_MAPPINGS["T1566.002"]),
                "explanation": f["explanation"]
            })

    # Balanced threat weighting
    has_headers = header_res["has_headers"]
    if not has_headers:
        # Raw body or unauthenticated paste
        if found_urls:
            composite = (body_res["score"] * 0.45) + (max_url_score * 0.55)
        else:
            composite = body_res["score"]
    else:
        # Full RFC-822 headers present
        if found_urls:
            composite = (header_res["score"] * 0.35) + (body_res["score"] * 0.30) + (max_url_score * 0.35)
        else:
            composite = (header_res["score"] * 0.50) + (body_res["score"] * 0.50)

    # In SOC operations, severe single vectors elevate overall risk
    max_component = max(header_res["score"] if has_headers else 0, body_res["score"], max_url_score)
    if max_component >= 65:
        composite = max(composite, max_component * 0.88)

    final_score = int(min(round(composite), 100))

    if final_score >= 80:
        risk_level = "CRITICAL"
        risk_color = THRESHOLDS["CRITICAL"]["color"]
        threat_classification = "Severe Phishing Campaign / Credential Exfiltration Attack"
    elif final_score >= 56:
        risk_level = "HIGH"
        risk_color = THRESHOLDS["HIGH"]["color"]
        threat_classification = "High-Likelihood Deceptive Spearphishing Attack"
    elif final_score >= 26:
        risk_level = "MEDIUM"
        risk_color = THRESHOLDS["MEDIUM"]["color"]
        threat_classification = "Suspicious Communication / Anomalous Routing"
    else:
        risk_level = "LOW"
        risk_color = THRESHOLDS["LOW"]["color"]
        threat_classification = "Legitimate / Verified Communication"

    all_findings = header_res["findings"] + body_res["findings"] + url_findings

    # Collect distinct MITRE techniques
    mitre_detected = {}
    for f in all_findings:
        if "mitre" in f and f["mitre"]:
            mitre_detected[f["mitre"]["id"]] = f["mitre"]

    soc_playbook = generate_soc_playbook(final_score)

    # Dual Perspective Reports
    subject = headers.get("Subject", "No Subject Header Detected")
    sender = headers.get("From", "Unauthenticated Source")
    general_user_report = generate_general_user_report(final_score, all_findings, url_results, subject, sender)

    formatted_iocs = {
        "domains": sorted(list(iocs["domains"])),
        "ips": sorted(list(iocs["ips"])),
        "urls": sorted(list(iocs["urls"]))
    }

    return {
        "score": final_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "threat_classification": threat_classification,
        "header_score": header_res["score"],
        "body_score": body_res["score"],
        "url_score": max_url_score,
        "findings_count": len(all_findings),
        "findings": all_findings,
        "mitre_techniques": list(mitre_detected.values()),
        "urls": url_results,
        "iocs": formatted_iocs,
        "subject": subject,
        "from": sender,
        "header_details": {
            "from": header_res.get("from", "-"),
            "display_name": header_res.get("display_name", "-"),
            "from_domain": header_res.get("from_domain", "-"),
            "return_path": headers.get("Return-Path", "-"),
            "return_path_domain": header_res.get("return_path_domain", "-"),
            "reply_to": headers.get("Reply-To", "-"),
            "reply_to_domain": header_res.get("reply_to_domain", "-"),
            "spf_status": header_res.get("spf_status", "NONE"),
            "dkim_status": header_res.get("dkim_status", "NONE"),
            "dmarc_status": header_res.get("dmarc_status", "NONE"),
            "date": headers.get("Date", "-"),
            "message_id": headers.get("Message-ID", "-")
        },
        "general_user_view": general_user_report,
        "body_preview": body_text[:280] + ("..." if len(body_text) > 280 else ""),
        "soc_playbook": soc_playbook,
        "disclaimer": FALSE_POSITIVE_DISCLAIMER
    }
