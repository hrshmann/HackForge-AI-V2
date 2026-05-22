import re
from urllib.parse import urlparse

suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'support', 'buzz']
brand_words = ['paypal', 'google', 'amazon', 'facebook', 'instagram', 'sbi', 'hdfc', 'icici']
sensitive_words = ['login', 'verify', 'update', 'secure', 'account', 'bank', 'confirm', 'password', 'signin']

def scan_live_url(url):
    score = 0
    reasons = []

    parsed = urlparse(url)
    hostname = parsed.netloc.lower()

    if not url.startswith("https"):
        score += 10
        reasons.append("URL does not use HTTPS")

    if len(url) > 50:
        score += 10
        reasons.append("Unusually long URL")

    if url.count('-') >= 2:
        score += 12
        reasons.append("Too many hyphens in URL")

    if '@' in url:
        score += 15
        reasons.append("@ symbol detected")

    if re.search(r'(\\d{1,3}\\.){3}\\d{1,3}', hostname):
        score += 20
        reasons.append("Raw IP address used")

    tld = hostname.split('.')[-1] if '.' in hostname else ''
    if tld in suspicious_tlds:
        score += 15
        reasons.append("Suspicious top-level domain")

    for word in brand_words:
        if word in url.lower():
            score += 8

    for word in sensitive_words:
        if word in url.lower():
            score += 5

    if 'login' in url.lower() and 'verify' in url.lower():
        score += 10
        reasons.append("Credential harvesting pattern")

    if 'update' in url.lower() and 'account' in url.lower():
        score += 10
        reasons.append("Account urgency pattern")

    confidence = min(score, 99)

    if confidence >= 70:
        status = "Highly Dangerous URL"
    elif confidence >= 40:
        status = "Suspicious URL"
    else:
        status = "Likely Safe URL"

    return {
        "status": status,
        "confidence": confidence,
        "reasons": reasons
    }