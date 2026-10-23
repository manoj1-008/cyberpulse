import socket, ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx

HEADERS = {
    "Strict-Transport-Security": ("High", "Enable HSTS after confirming HTTPS works for all intended subdomains."),
    "Content-Security-Policy": ("Medium", "Define a Content-Security-Policy appropriate to the application's resources."),
    "X-Content-Type-Options": ("Low", "Set X-Content-Type-Options: nosniff."),
    "Referrer-Policy": ("Low", "Set a Referrer-Policy that minimizes unnecessary referrer data."),
    "Permissions-Policy": ("Low", "Set a restrictive Permissions-Policy for browser capabilities not required."),
}

def check_https_asset(hostname: str):
    # Only call after the user has completed DNS TXT ownership verification.
    # Redirects are disabled and only HTTPS port 443 is contacted.
    evidence = []
    url = f"https://{hostname}/"
    try:
        with httpx.Client(timeout=8.0, follow_redirects=False, verify=True, trust_env=False) as client:
            response = client.get(url, headers={"User-Agent": "CyberGuardPulse-MVP/0.1"})
            for header, (severity, recommendation) in HEADERS.items():
                value = response.headers.get(header)
                if not value:
                    evidence.append({
                        "title": f"Missing {header}",
                        "severity": severity,
                        "evidence": f"GET {url} returned HTTP {response.status_code}; response header {header} was absent.",
                        "recommendation": recommendation
                    })
    except (httpx.HTTPError, ValueError) as exc:
        evidence.append({
            "title": "HTTPS assessment could not complete",
            "severity": "Info",
            "evidence": f"HTTPS request to the verified hostname failed: {type(exc).__name__}. No exploit or port scan was attempted.",
            "recommendation": "Confirm the hostname is publicly reachable over HTTPS and retry. Treat this as an assessment limitation, not proof of a vulnerability."
        })
    return evidence
