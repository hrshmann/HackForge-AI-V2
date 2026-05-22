import re
from typing import Dict


class SecurityHeadersAnalyzer:
    def __init__(self, headers: Dict):
        self.headers = {k.lower(): v for k, v in headers.items()} if headers else {}

    def analyze(self) -> Dict:
        results = {
            'missing_headers': [],
            'weak_headers': [],
            'good_headers': [],
            'vulnerabilities': [],
            'score': 0
        }

        header_checks = {
            'content-security-policy': self._check_csp,
            'strict-transport-security': self._check_hsts,
            'x-frame-options': self._check_frame_options,
            'x-content-type-options': self._check_content_type,
            'x-xss-protection': self._check_xss_protection,
            'referrer-policy': self._check_referrer_policy
        }

        total_score = 0
        max_score = len(header_checks) * 10

        for header_name, check_func in header_checks.items():
            header_value = self.headers.get(header_name)

            if header_value:
                check_result = check_func(header_value)
                total_score += check_result['score']

                if check_result['status'] == 'good':
                    results['good_headers'].append(header_name)
                elif check_result['status'] == 'weak':
                    results['weak_headers'].append({
                        'header': header_name,
                        'issue': check_result['issue']
                    })
            else:
                results['missing_headers'].append(header_name)
                results['vulnerabilities'].append({
                    'type': f'Missing {header_name}',
                    'severity': 'medium',
                    'description': self._get_header_description(header_name)
                })

        results['score'] = round((total_score / max_score) * 100, 2)
        return results

    def _check_csp(self, value: str) -> Dict:
        if 'unsafe-inline' in value or 'unsafe-eval' in value:
            return {'status': 'weak', 'score': 5, 'issue': 'Contains unsafe directives'}
        elif "default-src 'self'" in value:
            return {'status': 'good', 'score': 10}
        return {'status': 'good', 'score': 8}

    def _check_hsts(self, value: str) -> Dict:
        if 'max-age' not in value:
            return {'status': 'weak', 'score': 3, 'issue': 'Missing max-age directive'}

        max_age_match = re.search(r'max-age=(\d+)', value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                return {'status': 'weak', 'score': 6, 'issue': 'max-age too short'}

        return {'status': 'good', 'score': 10}

    def _check_frame_options(self, value: str) -> Dict:
        if value.upper() in ['DENY', 'SAMEORIGIN']:
            return {'status': 'good', 'score': 10}
        return {'status': 'weak', 'score': 5, 'issue': 'Should be DENY or SAMEORIGIN'}

    def _check_content_type(self, value: str) -> Dict:
        if value.lower() == 'nosniff':
            return {'status': 'good', 'score': 10}
        return {'status': 'weak', 'score': 5, 'issue': 'Invalid value'}

    def _check_xss_protection(self, value: str) -> Dict:
        if '1' in value:
            return {'status': 'good', 'score': 8}
        return {'status': 'weak', 'score': 3, 'issue': 'XSS filter disabled'}

    def _check_referrer_policy(self, value: str) -> Dict:
        strong = ['no-referrer', 'same-origin', 'strict-origin']
        if any(x in value.lower() for x in strong):
            return {'status': 'good', 'score': 10}
        return {'status': 'weak', 'score': 6, 'issue': 'Weak referrer policy'}

    def _get_header_description(self, header: str) -> str:
        descriptions = {
            'content-security-policy': 'Prevents XSS and data injection attacks',
            'strict-transport-security': 'Forces HTTPS connections',
            'x-frame-options': 'Prevents clickjacking attacks',
            'x-content-type-options': 'Prevents MIME-sniffing',
            'x-xss-protection': 'Enables browser XSS filtering',
            'referrer-policy': 'Controls referrer leakage'
        }
        return descriptions.get(header, 'Security header protection')
