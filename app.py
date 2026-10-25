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
from flask import Flask, render_template, request, jsonify, send_from_directory

from analyzer.email_analyzer import analyze_email
from analyzer.url_analyzer import analyze_url
from analyzer.heuristics import THRESHOLDS, FALSE_POSITIVE_DISCLAIMER

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(BASE_DIR, "templates")
if not os.path.exists(templates_dir):
    templates_dir = os.path.join(os.getcwd(), "templates")

static_dir = os.path.join(BASE_DIR, "static")
if not os.path.exists(static_dir):
    static_dir = os.path.join(os.getcwd(), "static")

samples_dir = os.path.join(BASE_DIR, "samples")
if not os.path.exists(samples_dir):
    samples_dir = os.path.join(os.getcwd(), "samples")

app = Flask(
    __name__,
    template_folder=templates_dir,
    static_folder=static_dir
)
SAMPLES_DIR = samples_dir


class VercelPathFixer:
    """Normalizes PATH_INFO when deployed behind Vercel serverless rewrites."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        from urllib.parse import parse_qs, urlencode
        import re

        query_string = environ.get("QUERY_STRING", "")
        if "__path__" in query_string:
            params = parse_qs(query_string, keep_blank_values=True)
            if "__path__" in params and params["__path__"]:
                raw_path = params.pop("__path__")[0]
                clean_path = re.sub(r"^/+", "/", raw_path)
                if clean_path in ("", "/", "/api/index.py", "/api/index", "/api", "/api/"):
                    environ["PATH_INFO"] = "/"
                else:
                    environ["PATH_INFO"] = clean_path
                environ["QUERY_STRING"] = urlencode(params, doseq=True)

        # Normalize SCRIPT_NAME to prevent prefix collisions
        environ["SCRIPT_NAME"] = ""

        # Normalize any direct access to entrypoint paths
        if environ.get("PATH_INFO") in ("/api/index.py", "/api/index", "/api", "/api/"):
            environ["PATH_INFO"] = "/"

        return self.wsgi_app(environ, start_response)


app.wsgi_app = VercelPathFixer(app.wsgi_app)


@app.route("/")
def index():
    """Renders the main PhishGuard Threat Intelligence interface."""
    return render_template("index.html")


@app.route("/static/<path:filename>")
def serve_static(filename):
    """Fallback route to ensure CSS and JS load across all cloud environments."""
    for candidate in [
        static_dir,
        os.path.join(BASE_DIR, "public", "static"),
        os.path.join(os.getcwd(), "public", "static"),
        os.path.join(os.getcwd(), "static")
    ]:
        file_path = os.path.join(candidate, filename)
        if os.path.exists(file_path):
            return send_from_directory(candidate, filename)
    return "Static file not found", 404


# Embedded synthetic corpus fallback for cloud/serverless environments
CORPUS_FILE = os.path.join(os.path.dirname(__file__), "analyzer", "sample_corpus.json")
EMBEDDED_SAMPLES = {}
if os.path.exists(CORPUS_FILE):
    try:
        import json
        with open(CORPUS_FILE, "r", encoding="utf-8") as f:
            EMBEDDED_SAMPLES = json.load(f)
    except Exception:
        pass


@app.route("/api/samples", methods=["GET"])
@app.route("/samples", methods=["GET"])
def get_samples():
    """Returns list of available synthetic test scenarios with metadata."""
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

    sample_list = []
    for fname, meta in descriptions.items():
        sample_list.append({
            "filename": fname,
            "title": meta["title"],
            "type": meta["type"],
            "category": meta["category"]
        })

    return jsonify({"samples": sample_list})


@app.route("/api/sample/<filename>", methods=["GET"])
@app.route("/sample/<filename>", methods=["GET"])
def get_sample_content(filename):
    """Loads raw text content of a synthetic sample file safely."""
    safe_name = os.path.basename(filename)
    file_path = os.path.join(SAMPLES_DIR, safe_name)

    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return jsonify({"filename": safe_name, "content": f.read()})
        except Exception:
            pass

    # Fallback to embedded corpus
    if safe_name in EMBEDDED_SAMPLES:
        return jsonify({"filename": safe_name, "content": EMBEDDED_SAMPLES[safe_name]})

    return jsonify({"error": "Scenario file not found"}), 404


@app.route("/api/analyze-email", methods=["POST"])
@app.route("/analyze-email", methods=["POST"])
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
@app.route("/analyze-url", methods=["POST"])
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
@app.route("/upload-eml", methods=["POST"])
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
