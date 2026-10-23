"""
PhishGuard: Threat Intelligence & Phishing Analysis Engine.
Web Application Backend (Flask REST API).

Standards: RFC 5322 (Email Format), RFC 7208 (SPF), RFC 6376 (DKIM),
RFC 7489 (DMARC), MITRE ATT&CK Enterprise Matrix v14
Stack: Python, Flask, Regex, email parsing, tldextract, BeautifulSoup
Safe Static Evaluation (Zero active network probes or external exploitation)
"""

import os
import glob
from flask import Flask, render_template, request, jsonify

from analyzer.email_analyzer import analyze_email
from analyzer.url_analyzer import analyze_url
from analyzer.heuristics import THRESHOLDS, FALSE_POSITIVE_DISCLAIMER

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")


@app.route("/")
def index():
    """Renders the main PhishGuard Threat Intelligence interface."""
    return render_template("index.html")


@app.route("/api/samples", methods=["GET"])
def get_samples():
    """Returns list of available synthetic test scenarios with metadata."""
    sample_files = glob.glob(os.path.join(SAMPLES_DIR, "*.eml"))
    sample_list = []

    descriptions = {
        "phishing_paypal_urgency.eml": {
            "title": "Phishing: PayPal Urgent Suspension (SPF/DKIM Spoof & Deceptive Subdomain)",
            "type": "phishing",
            "category": "Credential Harvesting"
        },
        "phishing_microsoft_mfa.eml": {
            "title": "Phishing: Microsoft 365 Security Alert (Typosquatting & Scare Tactics)",
            "type": "phishing",
            "category": "Brand Impersonation"
        },
        "phishing_ip_banking.eml": {
            "title": "Phishing: Chase Online Banking (Direct IP Host & Credential Theft)",
            "type": "phishing",
            "category": "Direct IP Exploit"
        },
        "phishing_shortener_crypto.eml": {
            "title": "Phishing: Binance Claim Portal (URL Shortener & Urgency)",
            "type": "phishing",
            "category": "Obfuscated Redirect"
        },
        "legitimate_amazon_receipt.eml": {
            "title": "Legitimate: Amazon Shipping Notification (Passing SPF/DKIM)",
            "type": "legitimate",
            "category": "E-Commerce Transaction"
        },
        "legitimate_github_security.eml": {
            "title": "Legitimate: GitHub Personal Access Token Alert",
            "type": "legitimate",
            "category": "Security Notification"
        },
        "legitimate_newsletter.eml": {
            "title": "Legitimate: CyberSec Weekly Digest Newsletter",
            "type": "legitimate",
            "category": "Industry Bulletin"
        }
    }

    for path in sorted(sample_files):
        fname = os.path.basename(path)
        meta = descriptions.get(fname, {"title": fname, "type": "unknown", "category": "Scenario"})
        sample_list.append({
            "filename": fname,
            "title": meta["title"],
            "type": meta["type"],
            "category": meta["category"]
        })

    return jsonify({"samples": sample_list})


@app.route("/api/sample/<filename>", methods=["GET"])
def get_sample_content(filename):
    """Loads raw text content of a synthetic sample file safely."""
    safe_name = os.path.basename(filename)
    file_path = os.path.join(SAMPLES_DIR, safe_name)

    if not os.path.exists(file_path):
        return jsonify({"error": "Scenario file not found"}), 404

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return jsonify({"filename": safe_name, "content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze-email", methods=["POST"])
def api_analyze_email():
    """Receives raw email string and returns threat detection analysis."""
    data = request.get_json(force=True, silent=True) or {}
    raw_email = data.get("email", "")

    if not raw_email or not raw_email.strip():
        return jsonify({"error": "Email content cannot be empty."}), 400

    try:
        result = analyze_email(raw_email)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/api/analyze-url", methods=["POST"])
def api_analyze_url():
    """Receives a standalone URL and returns heuristic threat analysis."""
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "")

    if not url or not url.strip():
        return jsonify({"error": "Target URL cannot be empty."}), 400

    try:
        result = analyze_url(url.strip())
        result["disclaimer"] = FALSE_POSITIVE_DISCLAIMER
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"URL analysis failed: {str(e)}"}), 500


@app.route("/api/upload-eml", methods=["POST"])
def api_upload_eml():
    """Handles direct .eml or .txt file upload for inspection."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file."}), 400

    try:
        content = file.read().decode("utf-8", errors="replace")
        if not content.strip():
            return jsonify({"error": "Uploaded file is empty."}), 400
        result = analyze_email(content)
        result["filename"] = file.filename
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Failed to process file: {str(e)}"}), 500


if __name__ == "__main__":
    print("\n[+] Initializing PhishGuard Threat Intelligence Platform on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=True)
