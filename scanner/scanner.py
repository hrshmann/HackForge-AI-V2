import asyncio
from typing import Dict, List

from scanner.crawler import AdvancedWebCrawler
from scanner.ml_analyzer import MLVulnerabilityAnalyzer
from scanner.active_tester import ActiveVulnerabilityTester


class HackForgeScanner:
    def __init__(self, target_url: str, max_depth: int = 3, max_pages: int = 50):
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_pages = max_pages

    async def run_full_scan(self) -> Dict:
        print(f"\n[1/4] Crawling target: {self.target_url}")
        crawler = AdvancedWebCrawler(self.target_url, self.max_depth, self.max_pages)
        crawl_data = await crawler.crawl()

        print(f"[2/4] Running ML vulnerability prediction")
        ml_engine = MLVulnerabilityAnalyzer(crawl_data)
        ml_predictions = ml_engine.analyze()

        print(f"[3/4] Running active exploitation tests")
        tester = ActiveVulnerabilityTester(crawl_data, ml_predictions)
        active_results = tester.run_tests()

        print(f"[4/4] Merging findings")
        final_findings = self._merge_results(ml_predictions, active_results)

        return {
            'target_url': self.target_url,
            'crawl_summary': {
                'pages_discovered': crawl_data.get('total_pages', 0),
                'forms_discovered': len(crawl_data.get('forms', [])),
                'inputs_discovered': len(crawl_data.get('inputs', [])),
                'cookies_discovered': len(crawl_data.get('cookies', [])),
                'technologies': crawl_data.get('technologies', [])
            },
            'raw_crawl_data': crawl_data,
            'ml_predictions': ml_predictions,
            'active_results': active_results,
            'final_findings': final_findings,
            'risk_score': self._calculate_risk_score(final_findings),
            'scan_status': 'completed'
        }

    def _merge_results(self, ml_predictions: Dict, active_results: List[Dict]) -> List[Dict]:
        merged = []
        active_keys = {(f.get('vulnerability_type'), f.get('url')) for f in active_results}

        # confirmed active findings first
        for finding in active_results:
            merged.append(finding)

        # bring in strongest ML suspects (controlled amount)
        ml_candidates = []

        for url, preds in ml_predictions.items():
            for vuln_type, pred in preds.items():
                conf = pred.get('confidence', 0)

                mapped_name = f"ML Suspected {vuln_type.replace('_', ' ').title()}"
                key = (mapped_name, url)

                if key in active_keys:
                    continue

                if conf >= 0.52:
                    ml_candidates.append({
                        'vulnerability_type': mapped_name,
                        'url': url,
                        'severity': 'low' if conf < 0.70 else 'medium',
                        'confidence': round(conf, 2),
                        'details': {
                            'reason': 'Heuristic anomaly detected by ML engine'
                        },
                        'cvss_score': 3.8 if conf < 0.70 else 5.2,
                        'cwe': 'Heuristic-ML'
                    })

        ml_candidates.sort(key=lambda x: x['confidence'], reverse=True)

        # only top 4 ML suspects to avoid clutter
        merged.extend(ml_candidates[:4])

        merged.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        return merged

    def _calculate_risk_score(self, findings: List[Dict]) -> float:
        if not findings:
            return 0.0

        weight_map = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2
        }

        total = 0
        for finding in findings:
            sev = finding.get('severity', 'low').lower()
            conf = finding.get('confidence', 0.5)
            total += weight_map.get(sev, 2) * conf

        normalized = min((total / (len(findings) * 10)) * 100, 100)
        return round(normalized, 2)


def run_scan(target_url: str, max_depth: int = 3, max_pages: int = 50):
    scanner = HackForgeScanner(target_url, max_depth, max_pages)
    return asyncio.run(scanner.run_full_scan())