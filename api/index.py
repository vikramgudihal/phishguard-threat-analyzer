import os
import sys
import re
from urllib.parse import parse_qs, urlencode

# Ensure the project root is in the Python path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app as flask_app


class VercelWSGIWrapper:
    """
    Normalizes Vercel serverless gateway PATH_INFO rewrites.
    Recovers the client's actual requested path from:
    1. Query parameter __path__ passed by vercel.json rewrite rule:
       {"source": "/((?!static/).*)", "destination": "/api/index.py?__path__=/$1"}
    2. Proxy headers (HTTP_X_FORWARDED_URI, HTTP_X_FORWARDED_PATH, RAW_URI)
    3. Existing PATH_INFO fallback.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        if "debug=1" in environ.get("QUERY_STRING", ""):
            import json
            data = {
                "PATH_INFO": environ.get("PATH_INFO"),
                "SCRIPT_NAME": environ.get("SCRIPT_NAME"),
                "QUERY_STRING": environ.get("QUERY_STRING"),
                "RAW_URI": environ.get("RAW_URI"),
                "headers": {k: v for k, v in environ.items() if k.startswith("HTTP_") or k.startswith("x-") or "URI" in k or "PATH" in k}
            }
            body = json.dumps(data, indent=2).encode("utf-8")
            start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
            return [body]

        target_path = None

        # 1. Check for __path__ passed via query string from vercel.json rewrite
        query_string = environ.get("QUERY_STRING", "")
        if "__path__" in query_string:
            params = parse_qs(query_string, keep_blank_values=True)
            if "__path__" in params and params["__path__"]:
                raw_path = params.pop("__path__")[0]
                target_path = re.sub(r"^/+", "/", raw_path)
                environ["QUERY_STRING"] = urlencode(params, doseq=True)

        # 2. Check proxy headers if target_path not found or is gateway rewrite
        if not target_path or target_path in ("/api/index.py", "/api/index", "/api", "/api/"):
            forwarded = (
                environ.get("HTTP_X_FORWARDED_URI") or
                environ.get("HTTP_X_FORWARDED_PATH") or
                environ.get("RAW_URI")
            )
            if forwarded:
                clean = forwarded.split("?")[0]
                if clean not in ("/api/index.py", "/api/index", "/api", "/api/"):
                    target_path = clean

        # 3. If target_path is still missing, fallback to current PATH_INFO
        if not target_path:
            target_path = environ.get("PATH_INFO", "/")

        # 4. Normalize root / entrypoint paths
        if target_path in ("", "/", "/api/index.py", "/api/index", "/api", "/api/"):
            environ["PATH_INFO"] = "/"
        else:
            environ["PATH_INFO"] = target_path

        return self.wsgi_app(environ, start_response)


app = VercelWSGIWrapper(flask_app)
