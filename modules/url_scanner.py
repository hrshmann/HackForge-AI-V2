import os
import re
import warnings
from urllib.parse import parse_qsl, urlparse

from model_loader import load_joblib_model


suspicious_tlds = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "support",
    "buzz", "click", "link", "zip", "mov", "quest", "country",
    "stream", "download", "cam", "icu", "shop", "rest",
]

brand_words = [
    "paypal", "google", "amazon", "facebook", "instagram", "sbi",
    "hdfc", "icici", "youtube", "microsoft", "apple", "netflix",
    "whatsapp", "telegram", "bank",
]

sensitive_words = [
    "login", "verify", "update", "secure", "account", "bank", "confirm",
    "password", "signin", "wallet", "otp", "kyc", "payment", "billing",
    "unlock", "limited", "suspend", "recover",
]

shortener_domains = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
    "lnkd.in", "s.id",
}

trusted_domains = {
    "google.com", "youtube.com", "youtu.be", "amazon.com", "facebook.com",
    "instagram.com", "microsoft.com", "apple.com", "netflix.com",
    "paypal.com", "whatsapp.com", "telegram.org",
}

URL_MODEL_PATH = os.path.join("models", "url_threat_model.pkl")
URL_FEATURES = [
    "NumDots", "SubdomainLevel", "PathLevel", "UrlLength", "NumDash",
    "NumDashInHostname", "AtSymbol", "TildeSymbol", "NumUnderscore",
    "NumPercent", "NumQueryComponents", "NumAmpersand", "NumHash",
    "NumNumericChars", "NoHttps", "RandomString", "IpAddress",
    "DomainInSubdomains", "DomainInPaths", "HttpsInHostname",
    "HostnameLength", "PathLength", "QueryLength", "DoubleSlashInPath",
    "NumSensitiveWords", "EmbeddedBrandName", "PctExtHyperlinks",
    "PctExtResourceUrls", "ExtFavicon", "InsecureForms",
    "RelativeFormAction", "ExtFormAction", "AbnormalFormAction",
    "PctNullSelfRedirectHyperlinks", "FrequentDomainNameMismatch",
    "FakeLinkInStatusBar", "RightClickDisabled", "PopUpWindow",
    "SubmitInfoToEmail", "IframeOrFrame", "MissingTitle",
    "ImagesOnlyInForm", "SubdomainLevelRT", "UrlLengthRT",
    "PctExtResourceUrlsRT", "AbnormalExtFormActionR",
    "ExtMetaScriptLinkRT", "PctExtNullSelfRedirectHyperlinksRT",
]


def _load_url_model():
    try:
        if os.path.exists(URL_MODEL_PATH):
            return load_joblib_model(URL_MODEL_PATH)
    except Exception:
        pass
    return None


URL_MODEL = _load_url_model()


def _normalise_for_parsing(url: str) -> str:
    cleaned = url.strip()
    if re.match(r"^[a-z][a-z0-9+.-]*://", cleaned, re.IGNORECASE):
        return cleaned
    return "http://" + cleaned


def _parsed_url(url: str):
    return urlparse(_normalise_for_parsing(url))


def _hostname(url: str) -> str:
    return (_parsed_url(url).hostname or "").lower().strip(".")


def _registered_domain(hostname: str) -> str:
    labels = [part for part in hostname.split(".") if part]
    if len(labels) < 2:
        return hostname
    return ".".join(labels[-2:])


def _domain_label(hostname: str) -> str:
    labels = [part for part in hostname.split(".") if part]
    if len(labels) < 2:
        return labels[0] if labels else ""
    return labels[-2]


def _is_ip_address(hostname: str) -> bool:
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", hostname))


def _is_trusted_host(hostname: str) -> bool:
    registered = _registered_domain(hostname)
    return registered in trusted_domains or any(hostname.endswith("." + item) for item in trusted_domains)


def _add_reason(reasons, reason):
    if reason not in reasons:
        reasons.append(reason)


def _looks_random(url: str) -> bool:
    tokens = re.findall(r"[a-z0-9]{10,}", url.lower())
    for token in tokens:
        has_alpha = any(ch.isalpha() for ch in token)
        has_digit = any(ch.isdigit() for ch in token)
        if has_alpha and has_digit:
            return True
    return False


def _url_features(url: str):
    parsed = _parsed_url(url)
    hostname = _hostname(url)
    registered = _registered_domain(hostname)
    domain = _domain_label(hostname)
    labels = [part for part in hostname.split(".") if part]
    subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""
    path = parsed.path or ""
    query = parsed.query or ""
    raw_lower = url.lower()
    subdomain_level = max(0, len(labels) - 2)
    url_length = len(url)

    embedded_brand = any(word in raw_lower for word in brand_words) and domain not in brand_words
    sensitive_count = sum(1 for word in sensitive_words if word in raw_lower)

    # The hosted model was trained with page-level fields too. URL-only scanning
    # cannot know those values, so neutral defaults keep ML as supporting signal.
    return [
        url.count("."),
        subdomain_level,
        len([item for item in path.split("/") if item]),
        url_length,
        url.count("-"),
        hostname.count("-"),
        int("@" in url),
        int("~" in url),
        url.count("_"),
        url.count("%"),
        len(parse_qsl(query, keep_blank_values=True)) if query else 0,
        url.count("&"),
        url.count("#"),
        sum(ch.isdigit() for ch in url),
        int(parsed.scheme.lower() != "https"),
        int(_looks_random(url)),
        int(_is_ip_address(hostname)),
        int(bool(domain and domain in subdomain)),
        int(bool(domain and domain in path.lower())),
        int("https" in hostname),
        len(hostname),
        len(path),
        len(query),
        int("//" in path),
        sensitive_count,
        int(embedded_brand),
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        -1 if subdomain_level >= 3 else (0 if subdomain_level == 2 else 1),
        -1 if url_length >= 75 else (0 if url_length >= 54 else 1),
        1, 1, 1, 1,
    ]


def _model_confidence(url: str):
    if URL_MODEL is None:
        return None

    features = _url_features(url)
    try:
        import pandas as pd

        frame = pd.DataFrame([features], columns=URL_FEATURES)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="X does not have valid feature names.*")
            probabilities = URL_MODEL.predict_proba(frame)[0]
    except Exception:
        return None

    positive_scores = [max(float(value), 0.0) for value in probabilities]
    total = sum(positive_scores)
    if not total or len(positive_scores) < 2:
        return None
    return max(0.0, min(100.0, (positive_scores[1] / total) * 100))


def _heuristic_score(url: str):
    score = 0
    reasons = []
    parsed = _parsed_url(url)
    hostname = _hostname(url)
    registered = _registered_domain(hostname)
    domain = _domain_label(hostname)
    lower_url = url.lower()

    if not re.match(r"^https://", url.strip(), re.IGNORECASE):
        score += 12
        _add_reason(reasons, "URL does not use HTTPS")

    if len(url) > 75:
        score += 18
        _add_reason(reasons, "Very long URL")
    elif len(url) > 50:
        score += 10
        _add_reason(reasons, "Unusually long URL")

    if url.count("-") >= 3:
        score += 16
        _add_reason(reasons, "Many hyphens in URL")
    elif url.count("-") >= 2:
        score += 10
        _add_reason(reasons, "Multiple hyphens in URL")

    if "@" in url:
        score += 25
        _add_reason(reasons, "@ symbol can hide the real destination")

    if _is_ip_address(hostname):
        score += 28
        _add_reason(reasons, "Raw IP address used instead of a domain")

    if registered in shortener_domains:
        score += 35
        _add_reason(reasons, "Shortened URL hides the final destination")

    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in suspicious_tlds:
        score += 18
        _add_reason(reasons, "High-risk domain ending")

    sensitive_hits = [word for word in sensitive_words if word in lower_url]
    if sensitive_hits:
        score += min(30, len(sensitive_hits) * 6)
        _add_reason(reasons, "Credential or account-related wording")

    brand_hits = [word for word in brand_words if word in lower_url]
    if brand_hits and domain not in brand_hits:
        score += 22
        _add_reason(reasons, "Brand name appears outside its official domain")

    if "login" in lower_url and "verify" in lower_url:
        score += 16
        _add_reason(reasons, "Login verification phishing pattern")

    if "update" in lower_url and "account" in lower_url:
        score += 14
        _add_reason(reasons, "Account update urgency pattern")

    if parsed.scheme.lower() == "https" and "https" in hostname:
        score += 16
        _add_reason(reasons, "The word HTTPS appears inside the hostname")

    if _looks_random(url):
        score += 14
        _add_reason(reasons, "Random-looking token in URL")

    if _is_trusted_host(hostname) and not any(
        reason in reasons
        for reason in [
            "@ symbol can hide the real destination",
            "Raw IP address used instead of a domain",
            "The word HTTPS appears inside the hostname",
        ]
    ):
        score = min(score, 18)

    return min(score, 99), reasons


def _status_from_score(score: float) -> str:
    if score >= 70:
        return "Highly Dangerous URL"
    if score >= 25:
        return "Suspicious URL"
    return "Likely Safe URL"


def scan_live_url(url):
    score, reasons = _heuristic_score(url)
    ml_confidence = _model_confidence(url)
    hostname = _hostname(url)

    if ml_confidence is not None:
        # The model includes page-level training fields that are unavailable in
        # URL-only mode, so never let ML alone condemn a known clean host.
        if _is_trusted_host(hostname) and score < 25:
            score = max(score, min(ml_confidence, 18))
        elif score >= 18 or ml_confidence >= 70:
            if ml_confidence > score:
                _add_reason(reasons, "ML model flagged phishing-like URL structure")
            score = max(score, ml_confidence)

    confidence = round(min(score, 99), 1)

    return {
        "status": _status_from_score(confidence),
        "confidence": confidence,
        "reasons": reasons,
    }
