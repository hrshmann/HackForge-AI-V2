def generate_ai_explanation(scan_type, result, indicators):
    status = result['status']
    confidence = result['confidence']

    if scan_type == "Text Communication Scan":
        if "Dangerous" in status:
            return f"""
HackForge AI has identified this communication as potentially malicious with a detection confidence of {confidence}%.
The message contains several social engineering patterns commonly used in phishing and scam campaigns, including {', '.join(indicators)}.
Such communications are typically designed to create urgency, obtain sensitive credentials, or manipulate the victim into clicking harmful links.
Users are advised to avoid responding and verify the sender through trusted channels.
"""
        else:
            return f"""
HackForge AI classified this communication as likely legitimate with a confidence of {confidence}%.
No severe phishing or scam indicators were detected in the textual content.
However, users should still maintain normal verification practices when dealing with unknown senders.
"""

    if scan_type == "URL Threat Scan":
        if "Dangerous" in status or "Suspicious" in status:
            return f"""
HackForge AI classified the submitted URL as a potentially unsafe web destination with a confidence of {confidence}%.
The link exhibits phishing-oriented structural anomalies such as {', '.join(indicators)}.
These patterns are frequently associated with credential harvesting pages, fake login portals, or malicious redirect campaigns.
Opening such links may expose users to account compromise or malware delivery.
"""
        else:
            return f"""
HackForge AI found the submitted URL to be relatively safe with a confidence of {confidence}%.
No strong phishing-oriented lexical abnormalities were detected within the domain structure.
Standard browsing caution is still recommended for unfamiliar websites.
"""