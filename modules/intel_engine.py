def text_risk_indicators(message):
    msg = message.lower()
    indicators = []

    if any(word in msg for word in ['urgent', 'immediately', 'suspended', 'warning']):
        indicators.append("Urgency language detected")

    if any(word in msg for word in ['bank', 'account', 'pan', 'kyc', 'otp', 'payment']):
        indicators.append("Financial credential reference")

    if any(word in msg for word in ['click', 'link', 'verify', 'login', 'signin']):
        indicators.append("Suspicious action request")

    if any(word in msg for word in ['winner', 'prize', 'reward', 'gift', 'lottery']):
        indicators.append("Reward bait wording")

    if any(word in msg for word in ['password', 'confirm', 'update']):
        indicators.append("Credential update attempt")

    return indicators


def url_risk_indicators(url):
    u = url.lower()
    indicators = []

    if not u.startswith("https"):
        indicators.append("Non-HTTPS insecure link")

    if len(u) > 50:
        indicators.append("Long suspicious URL")

    if u.count('-') >= 2:
        indicators.append("Multiple hyphens detected")

    if '@' in u:
        indicators.append("@ redirect deception")

    if any(tld in u for tld in ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']):
        indicators.append("High-risk domain suffix")

    if any(word in u for word in ['login', 'verify', 'update', 'secure', 'account']):
        indicators.append("Credential phishing keywords")

    if any(word in u for word in ['paypal', 'sbi', 'hdfc', 'google', 'amazon']):
        indicators.append("Brand impersonation pattern")

    return indicators


def recommended_actions(status):
    if "Dangerous" in status or "Suspicious" in status:
        return [
            "Do not click or respond to the content",
            "Do not share passwords, OTPs, or banking details",
            "Verify the sender or domain manually",
            "Block, report, and discard the threat source"
        ]
    else:
        return [
            "No major threat patterns detected",
            "Still verify unknown senders as a safety practice"
        ]