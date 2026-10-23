"""
Command-Line Interface (CLI) for PhishGuard Threat Intelligence Platform.

Usage:
    python cli.py --file samples/phishing_paypal_urgency.eml
    python cli.py --file samples/phishing_paypal_urgency.eml --audience user
    python cli.py --url "http://paypal.com.verify-billing.xyz/login"
    python cli.py --run-corpus
    python cli.py --json --file samples/phishing_microsoft_mfa.eml
"""

import sys
import os
import argparse
import json
import glob

from analyzer.email_analyzer import analyze_email
from analyzer.url_analyzer import analyze_url
from analyzer.heuristics import FALSE_POSITIVE_DISCLAIMER


def print_banner():
    banner = """
================================================================================
   PHISHGUARD: THREAT INTELLIGENCE & HEURISTICS ANALYZER
   Dual-Perspective Engine: Employee Awareness & SOC Blue Team Forensics
   Standards: RFC 5322, RFC 7208, RFC 6376, RFC 7489, MITRE ATT&CK v14
================================================================================
"""
    print(banner)


def display_general_user_view(result: dict, filepath: str = None):
    uv = result.get("general_user_view", {})
    print("\n" + "=" * 80)
    if filepath:
        print(f"[*] ARTIFACT: {filepath}")
    print(f"[*] STATUS:   [{uv.get('verdict_badge', 'UNKNOWN')}] (Risk Score: {result['score']}/100)")
    print(f"[*] VERDICT:  {uv.get('verdict_heading', '')}")
    print("-" * 80)
    print(f"\n[EXPLANATION]\n{uv.get('verdict_desc', '')}\n")

    red_flags = uv.get("red_flags", [])
    if red_flags:
        print("[KEY RED FLAGS IDENTIFIED]:")
        for idx, rf in enumerate(red_flags, 1):
            print(f"  {idx}. [{rf['severity']}] {rf['title']}")
            print(f"     -> {rf['explanation']}")

    actions = uv.get("safety_actions", [])
    if actions:
        print("\n[RECOMMENDED SAFETY ACTIONS]:")
        for act in actions:
            print(f"  • {act}")

    user_links = uv.get("user_links", [])
    if user_links:
        print("\n[INSPECTED LINKS]:")
        for ul in user_links:
            print(f"  • {ul['domain']} [{ul['risk_level']}]: {ul['verdict']}")

    print("\n" + "-" * 80)
    print(f"[!] {FALSE_POSITIVE_DISCLAIMER}")
    print("=" * 80 + "\n")


def display_soc_analyst_view(result: dict, filepath: str = None):
    print("\n" + "=" * 80)
    if filepath:
        print(f"[*] ARTIFACT SOURCE: {filepath}")
    print(f"[*] TARGET SUBJECT:  {result.get('subject', 'N/A')}")
    print(f"[*] SENDER ENVELOPE: {result.get('from', 'N/A')}")
    print("-" * 80)
    print(f"[*] THREAT LEVEL:    [{result['risk_level']}] (Score: {result['score']}/100)")
    print(f"[*] CLASSIFICATION:  {result['threat_classification']}")
    print(f"[*] SUB-VECTORS:     Headers: {result['header_score']}/100 | Body NLP: {result['body_score']}/100 | URLs: {result['url_score']}/100")
    print("-" * 80)

    # RFC-822 Authentication Details
    hd = result.get("header_details", {})
    print("[RFC-822 AUTHENTICATION & ROUTING MATRIX]:")
    print(f"  • From Domain:        {hd.get('from_domain', '-')}")
    print(f"  • Return-Path Domain: {hd.get('return_path_domain', '-')}")
    print(f"  • Reply-To Domain:    {hd.get('reply_to_domain', '-')}")
    print(f"  • SPF Status:         [{hd.get('spf_status', 'NONE')}]")
    print(f"  • DKIM Status:        [{hd.get('dkim_status', 'NONE')}]")
    print(f"  • DMARC Status:       [{hd.get('dmarc_status', 'NONE')}]")

    # MITRE ATT&CK Techniques
    if result.get("mitre_techniques"):
        print("\n[CORRELATED MITRE ATT&CK TECHNIQUES]:")
        for m in result["mitre_techniques"]:
            print(f"  • [{m['id']}] {m['name']} (Tactic: {m['tactic']})")

    # Detailed Findings
    print("\n[DETECTED FORENSIC THREAT ANOMALIES]:")
    if not result['findings']:
        print("  -> None. All checks passed standard legitimacy heuristics.")
    else:
        for idx, finding in enumerate(result['findings'], 1):
            sev = finding.get('severity', 'INFO')
            pts = finding.get('points', 0)
            rule = finding.get('rule', '')
            cat = finding.get('category', '')
            exp = finding.get('explanation', '')
            mitre_id = f"[{finding['mitre']['id']}] " if finding.get('mitre') else ""
            print(f"  {idx}. [{sev}] (+{pts} pts) {mitre_id}[{cat} / {rule}]")
            print(f"     Explanation: {exp}")

    # URLs Table
    if result.get('urls'):
        print("\n[EXTRACTED HYPERLINKS INFRASTRUCTURE]:")
        for u in result['urls']:
            print(f"  - Target URL: {u.get('defanged_url', u['url'])}")
            print(f"    Domain: {u.get('defanged_domain', u['registered_domain'])} | Entropy: {u.get('entropy', 0.0)} | Risk: [{u['risk_level']}] ({u['score']}/100)")
            for uf in u.get('findings', []):
                print(f"      * {uf['rule']}: {uf['explanation']}")

    # Indicators of Compromise (IoCs)
    if result.get('iocs'):
        print("\n[DEFANGED INDICATORS OF COMPROMISE (IoCs)]:")
        iocs = result['iocs']
        if iocs.get('domains'):
            print(f"  - Target Domains: {', '.join(iocs['domains'])}")
        if iocs.get('ips'):
            print(f"  - Host/Relay IPs: {', '.join(iocs['ips'])}")
        if iocs.get('urls'):
            print(f"  - Defanged URLs ({len(iocs['urls'])}):")
            for u in iocs['urls']:
                print(f"      * {u}")

    # Blue Team Playbook
    print("\n[SOC DEFENSIVE CONTAINMENT PLAYBOOK]:")
    for rec in result.get('soc_playbook', []):
        print(f"  • {rec}")

    print("\n" + "-" * 80)
    print(f"[!] {FALSE_POSITIVE_DISCLAIMER}")
    print("=" * 80 + "\n")


def display_url_results(result: dict):
    print("\n" + "=" * 80)
    print(f"[*] TARGET URL:          {result['url']}")
    print(f"[*] DEFANGED URL:        {result.get('defanged_url', result['url'])}")
    print(f"[*] APEX DOMAIN:         {result['registered_domain']} (TLD: .{result.get('tld', '')})")
    print(f"[*] SHANNON ENTROPY:     {result.get('entropy', 0.0)}/5.0")
    print(f"[*] THREAT SCORE:        {result['score']}/100  [{result['risk_level']}]")
    print("-" * 80)
    print("[!] DETECTED THREAT INDICATORS:")
    if not result['findings']:
        print("  -> No adversarial indicators detected in target URL structure.")
    else:
        for idx, finding in enumerate(result['findings'], 1):
            mitre_id = f"[{finding['mitre']['id']}] " if finding.get('mitre') else ""
            print(f"  {idx}. [{finding['severity']}] (+{finding['points']} pts) {mitre_id}{finding['rule']}")
            print(f"     {finding['explanation']}")
    print("-" * 80)
    print(f"[!] {FALSE_POSITIVE_DISCLAIMER}")
    print("=" * 80 + "\n")


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="PhishGuard Threat Intelligence & Heuristics Analyzer")
    parser.add_argument("--file", "-f", help="Path to raw email file (.eml or text)")
    parser.add_argument("--url", "-u", help="Specific URL to scan")
    parser.add_argument("--run-corpus", "-c", action="store_true", help="Run analyzer across all samples in samples/ directory")
    parser.add_argument("--audience", "-a", choices=["analyst", "user"], default="analyst", help="Output view perspective: 'analyst' (SOC Forensics) or 'user' (Employee Awareness)")
    parser.add_argument("--json", "-j", action="store_true", help="Output results in machine-readable JSON")

    args = parser.parse_args()

    if args.url:
        result = analyze_url(args.url)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            display_url_results(result)
        return

    if args.file:
        if not os.path.exists(args.file):
            print(f"[-] Error: Target artifact not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        result = analyze_email(content)
        if args.json:
            print(json.dumps(result, indent=2))
        elif args.audience == "user":
            display_general_user_view(result, filepath=args.file)
        else:
            display_soc_analyst_view(result, filepath=args.file)
        return

    if args.run_corpus:
        samples = glob.glob(os.path.join("samples", "*.eml"))
        if not samples:
            print("[-] No test samples found in samples/ directory.")
            return

        print(f"[*] Running multi-vector heuristics across {len(samples)} synthetic test artifacts...\n")
        summary = []
        for s in sorted(samples):
            with open(s, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            res = analyze_email(content)
            summary.append({
                "sample": os.path.basename(s),
                "score": res["score"],
                "level": res["risk_level"],
                "mitre": len(res.get("mitre_techniques", [])),
                "flags": res["findings_count"]
            })
            if args.audience == "user":
                display_general_user_view(res, filepath=s)
            else:
                display_soc_analyst_view(res, filepath=s)

        print("\n" + "=" * 80)
        print("                 SYNTHETIC TEST CORPUS BENCHMARK TABLE")
        print("=" * 80)
        print(f"{'Sample File':<36} | {'Score':<6} | {'Risk Level':<10} | {'MITRE TTPs':<10} | {'Flags':<6}")
        print("-" * 80)
        for row in summary:
            print(f"{row['sample']:<36} | {row['score']:<6} | {row['level']:<10} | {row['mitre']:<10} | {row['flags']:<6}")
        print("=" * 80)
        return

    print("Usage options:")
    print("  python cli.py --file samples/phishing_paypal_urgency.eml")
    print("  python cli.py --file samples/phishing_paypal_urgency.eml --audience user")
    print("  python cli.py --url http://paypal.com.verify-billing.xyz")
    print("  python cli.py --run-corpus")
    print("  python app.py  (Launch web application on http://127.0.0.1:5000)")


if __name__ == "__main__":
    main()
