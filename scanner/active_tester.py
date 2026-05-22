import requests
import difflib
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from tools.sqlmap_wrapper import SQLMapWrapper
from tools.xsstrike_wrapper import XSStrikeWrapper
from tools.security_headers import SecurityHeadersAnalyzer


class ActiveVulnerabilityTester:
    def __init__(self, crawl_data: Dict, ml_predictions: Dict = None):
        self.crawl_data = crawl_data or {}
        self.ml_predictions = ml_predictions or {}
        self.results = []
        self.tested_targets = set()
        self.http_headers = {
            "User-Agent": "Mozilla/5.0 HackForgeAI Security Scanner",
            "Accept": "*/*"
        }

    def run_tests(self, max_workers: int = 3) -> List[Dict]:
        test_tasks = self._plan_tests()

        if not test_tasks:
            return []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._execute_test, task): task
                for task in test_tasks
            }

            for future in as_completed(futures):
                try:
                    result = future.result(timeout=180)
                    if result:
                        if isinstance(result, list):
                            self.results.extend(result)
                        else:
                            self.results.append(result)
                except Exception as e:
                    print(f"Test failed: {e}")

        return self._deduplicate_results(self.results)

    def _plan_tests(self) -> List[Dict]:
        tasks = []
        suspicious_targets = set()

        for url, vulns in self.ml_predictions.items():
            if url == 'site-wide':
                continue
            if any(v in vulns for v in ['sql_injection', 'xss', 'csrf']):
                suspicious_targets.add(url)

        for form in self.crawl_data.get('forms', []):
            form_url = form.get('action')
            if not form_url or form_url in self.tested_targets:
                continue

            if suspicious_targets and form_url not in suspicious_targets:
                continue

            self.tested_targets.add(form_url)
            payload_data = self._extract_form_data(form)

            tasks.append({
                'type': 'sql_injection',
                'target': form_url,
                'method': form.get('method', 'GET'),
                'data': payload_data,
                'priority': 'high'
            })

            tasks.append({
                'type': 'xss',
                'target': form_url,
                'method': form.get('method', 'GET'),
                'data': payload_data,
                'priority': 'high'
            })

            if not form.get('has_csrf') and form.get('method', '').upper() == 'POST':
                tasks.append({
                    'type': 'csrf',
                    'target': form_url,
                    'method': 'POST',
                    'priority': 'medium'
                })

        base_target = (
            self.crawl_data.get('pages')[0].get('url', 'site-wide')
            if self.crawl_data.get('pages')
            else 'site-wide'
        )

        tasks.append({
            'type': 'security_headers',
            'target': base_target,
            'headers': self.crawl_data.get('headers', {}),
            'priority': 'low'
        })

        for cookie in self.crawl_data.get('cookies', [])[:2]:
            tasks.append({
                'type': 'cookie_security',
                'cookie': cookie,
                'priority': 'medium'
            })

        priority_map = {'high': 0, 'medium': 1, 'low': 2}
        tasks.sort(key=lambda x: priority_map[x['priority']])

        return tasks[:10]

    def _execute_test(self, task: Dict):
        if task['type'] == 'sql_injection':
            return self._test_sql_injection(task)
        elif task['type'] == 'xss':
            return self._test_xss(task)
        elif task['type'] == 'security_headers':
            return self._test_security_headers(task)
        elif task['type'] == 'csrf':
            return self._test_csrf(task)
        elif task['type'] == 'cookie_security':
            return self._test_cookie_security(task)
        return None

    def _test_sql_injection(self, task: Dict):
        sqlmap = SQLMapWrapper(task['target'], task.get('data'))
        sqlmap_result = sqlmap.scan(level=2, risk=1, timeout=60)

        manual_result = self._manual_sql_probe(task['target'], task.get('data'))
        final_conf = max(sqlmap_result.get('confidence', 0), manual_result.get('confidence', 0))

        if sqlmap_result.get('vulnerable') or manual_result.get('vulnerable'):
            return {
                'vulnerability_type': 'SQL Injection',
                'url': task['target'],
                'method': task['method'],
                'severity': 'critical',
                'confidence': round(final_conf, 2),
                'details': {
                    'sqlmap': sqlmap_result.get('details', {}),
                    'manual_probe': manual_result.get('details', {})
                },
                'cvss_score': 9.8,
                'cwe': 'CWE-89',
                'remediation': self._get_sql_injection_remediation()
            }
        return None

    def _manual_sql_probe(self, url: str, data: Dict):
        if not data:
            return {'vulnerable': False, 'confidence': 0.0, 'details': {}}

        try:
            payload_true = "' OR '1'='1"
            payload_false = "' AND '1'='2"

            true_data = {k: payload_true for k in data.keys()}
            false_data = {k: payload_false for k in data.keys()}

            r1 = requests.post(url, data=true_data, timeout=6, verify=False, headers=self.http_headers)
            r2 = requests.post(url, data=false_data, timeout=6, verify=False, headers=self.http_headers)

            similarity = difflib.SequenceMatcher(None, r1.text[:700], r2.text[:700]).ratio()
            combined = (r1.text + r2.text).lower()

            sql_errors = ['sql syntax', 'mysql', 'syntax error', 'database error', 'odbc', 'sqlite']

            if similarity < 0.72 or any(err in combined for err in sql_errors):
                return {
                    'vulnerable': True,
                    'confidence': 0.80,
                    'details': {'response_similarity': similarity}
                }
        except Exception:
            pass

        return {'vulnerable': False, 'confidence': 0.0, 'details': {}}

    def _test_xss(self, task: Dict):
        xs = XSStrikeWrapper(task['target'])
        xs_result = xs.scan(timeout=60)

        reflected_result = self._manual_xss_probe(task['target'], task.get('data'))
        final_conf = max(xs_result.get('confidence', 0), reflected_result.get('confidence', 0))

        if xs_result.get('vulnerable') or reflected_result.get('vulnerable'):
            xss_types = xs_result.get('xss_type', ['Reflected'])

            return {
                'vulnerability_type': f"XSS ({', '.join(xss_types)})",
                'url': task['target'],
                'method': task['method'],
                'severity': 'high',
                'confidence': round(final_conf, 2),
                'details': {
                    'xsstrike': xs_result.get('details', {}),
                    'manual_probe': reflected_result.get('details', {})
                },
                'cvss_score': 8.1,
                'cwe': 'CWE-79',
                'remediation': self._get_xss_remediation()
            }
        return None

    def _manual_xss_probe(self, url: str, data: Dict):
        if not data:
            return {'vulnerable': False, 'confidence': 0.0, 'details': {}}

        try:
            payload = '<script>alert(1)</script>'
            xss_data = {k: payload for k in data.keys()}

            r = requests.post(url, data=xss_data, timeout=6, verify=False, headers=self.http_headers)
            body = r.text.lower()

            if payload.lower() in body or '&lt;script&gt;alert(1)&lt;/script&gt;' in body:
                return {
                    'vulnerable': True,
                    'confidence': 0.76,
                    'details': {'payload_reflected': True}
                }
        except Exception:
            pass

        return {'vulnerable': False, 'confidence': 0.0, 'details': {}}

    def _test_security_headers(self, task: Dict):
        analyzer = SecurityHeadersAnalyzer(task.get('headers', {}))
        result = analyzer.analyze()

        if result['score'] < 65:
            return {
                'vulnerability_type': 'Security Misconfiguration',
                'url': task['target'],
                'severity': 'medium',
                'confidence': 0.78,
                'details': result,
                'cvss_score': 5.1,
                'cwe': 'CWE-16',
                'remediation': self._get_security_headers_remediation(result)
            }
        return None

    def _test_csrf(self, task: Dict):
        return {
            'vulnerability_type': 'Potential CSRF Exposure',
            'url': task['target'],
            'severity': 'medium',
            'confidence': 0.72,
            'details': {'reason': 'POST form without anti-CSRF token'},
            'cvss_score': 6.1,
            'cwe': 'CWE-352'
        }

    def _test_cookie_security(self, task: Dict):
        cookie = task['cookie']
        issues = []

        if not cookie.get('secure'):
            issues.append('Missing Secure flag')
        if not cookie.get('httponly'):
            issues.append('Missing HttpOnly flag')

        if issues:
            return {
                'vulnerability_type': 'Insecure Cookie Configuration',
                'url': 'site-wide',
                'severity': 'medium',
                'confidence': 0.74,
                'details': {
                    'cookie_name': cookie.get('name'),
                    'issues': issues
                },
                'cvss_score': 5.6,
                'cwe': 'CWE-614'
            }
        return None

    def _deduplicate_results(self, findings: List[Dict]) -> List[Dict]:
        dedup = {}
        for f in findings:
            key = (f.get('vulnerability_type'), f.get('url'))
            if key not in dedup or f.get('confidence', 0) > dedup[key].get('confidence', 0):
                dedup[key] = f
        return list(dedup.values())

    def _extract_form_data(self, form: Dict) -> Dict:
        data = {}
        for field in form.get('inputs', []):
            name = field.get('name')
            ftype = field.get('type', 'text').lower()

            if not name:
                continue

            if 'email' in name or ftype == 'email':
                data[name] = 'test@example.com'
            elif 'id' in name or 'num' in name:
                data[name] = '1'
            elif ftype == 'password':
                data[name] = 'Password123'
            else:
                data[name] = 'test'
        return data

    def _get_sql_injection_remediation(self):
        return {'summary': 'Use parameterized queries and prepared statements.'}

    def _get_xss_remediation(self):
        return {'summary': 'Sanitize user input and encode reflected output.'}

    def _get_security_headers_remediation(self, result: Dict):
        return {'summary': 'Implement missing HTTP security headers and secure defaults.'}