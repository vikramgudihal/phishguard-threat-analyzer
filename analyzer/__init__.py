"""
Phishing Awareness Analyzer Package
"""
from analyzer.heuristics import THRESHOLDS, FALSE_POSITIVE_DISCLAIMER
from analyzer.url_analyzer import analyze_url
from analyzer.email_analyzer import analyze_email

__all__ = ["analyze_email", "analyze_url", "THRESHOLDS", "FALSE_POSITIVE_DISCLAIMER"]
