import joblib
from pathlib import Path
from typing import Dict
from collections import defaultdict


class MLVulnerabilityAnalyzer:
    def __init__(self, crawl_data: Dict):
        self.crawl_data = crawl_data
        self.model = self._load_model()

    def _load_model(self):
        possible_paths = [
            Path(__file__).parent.parent / "models" / "web_vuln_ml_model.pkl",
            "models/web_vuln_ml_model.pkl"
        ]

        for path in possible_paths:
            path = Path(path)
            if path.exists():
                return joblib.load(path)

        raise FileNotFoundError("web_vuln_ml_model.pkl not found inside models folder")

    def analyze(self) -> Dict:
        predictions = defaultdict(dict)

        self._analyze_forms(predictions)
        self._analyze_pages(predictions)
        self._analyze_cookies(predictions)

        return dict(predictions)

    def _predict_vector(self, features):
        prob_sets = self.model.predict_proba([features])

        probs = []
        for prob in prob_sets:
            if len(prob[0]) > 1:
                probs.append(float(prob[0][1]))
            else:
                probs.append(0.0)

        return probs

    def _analyze_forms(self, predictions: Dict):
        for form in self.crawl_data.get("forms", []):
            url = form.get("action")
            if not url:
                continue

            input_names = [inp.get("name", "").lower() for inp in form.get("inputs", [])]
            method = form.get("method", "GET").upper()

            suspicious_sql_fields = sum(
                1 for name in input_names
                if any(k in name for k in ["id", "uid", "user", "account", "search", "query", "item"])
            )

            suspicious_xss_fields = sum(
                1 for name in input_names
                if any(k in name for k in ["comment", "message", "search", "feedback", "name"])
            )

            features = [
                len(form.get("inputs", [])),
                1 if method == "POST" else 0,
                1 if form.get("is_login") else 0,
                1 if form.get("has_csrf") else 0,
                suspicious_sql_fields,
                suspicious_xss_fields,
                70,
                0,
                0,
                3,
                0
            ]

            sql_prob, xss_prob, csrf_prob, _, _ = self._predict_vector(features)

            if sql_prob >= 0.78:
                predictions[url]["sql_injection"] = {
                    "confidence": round(sql_prob, 2),
                    "severity": "high"
                }

            if xss_prob >= 0.76:
                predictions[url]["xss"] = {
                    "confidence": round(xss_prob, 2),
                    "severity": "medium"
                }

            if csrf_prob >= 0.74:
                predictions[url]["csrf"] = {
                    "confidence": round(csrf_prob, 2),
                    "severity": "medium"
                }

    def _analyze_pages(self, predictions: Dict):
        for page in self.crawl_data.get("pages", []):
            url = page.get("url")
            if not url:
                continue

            sec = page.get("security_headers", {})
            security_score = sec.get("security_score", 60)

            scripts_count = page.get("scripts_count", 0)
            resources = " ".join(page.get("external_resources", [])).lower()

            features = [
                2,
                0,
                0,
                1,
                0,
                1,
                security_score,
                0,
                0,
                scripts_count,
                1 if ("api" in url.lower() or "json" in resources) else 0
            ]

            _, _, _, sec_prob, _ = self._predict_vector(features)

            if sec_prob >= 0.72:
                predictions[url]["security_misconfiguration"] = {
                    "confidence": round(sec_prob, 2),
                    "severity": "medium"
                }

    def _analyze_cookies(self, predictions: Dict):
        for cookie in self.crawl_data.get("cookies", []):
            domain = cookie.get("domain") or "site-wide"

            features = [
                1,
                0,
                0,
                1,
                0,
                0,
                80,
                0 if cookie.get("secure") else 1,
                0 if cookie.get("httponly") else 1,
                1,
                0
            ]

            _, _, _, _, cookie_prob = self._predict_vector(features)

            if cookie_prob >= 0.75:
                predictions[domain]["insecure_cookie"] = {
                    "confidence": round(cookie_prob, 2),
                    "severity": "medium"
                }