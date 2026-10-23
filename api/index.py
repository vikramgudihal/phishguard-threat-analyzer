import os
import sys

# Ensure the project root is in the Python path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app as flask_app


class VercelWSGIWrapper:
    """
    Normalizes Vercel serverless gateway PATH_INFO rewrites.
    Ensures that rewritten paths like /api/index.py or /api/index
    properly map to root '/' for Flask template rendering.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path in ("/api/index.py", "/api/index", "/api", "/api/"):
            environ["PATH_INFO"] = "/"
        return self.wsgi_app(environ, start_response)


app = VercelWSGIWrapper(flask_app)
