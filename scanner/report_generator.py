print("REPORT FILE LOADED")

from typing import Dict, List
from datetime import datetime
import json

class ReportGenerator:
    def __init__(self, scan_data: Dict):
        self.scan_data = scan_data
        self.timestamp = datetime.now()
    
    def generate(self) -> Dict:
        return {
            'metadata': self._generate_metadata(),
            'executive_summary': self._generate_executive_summary(),
            'findings': self._organize_findings(),
            'recommendations': self._generate_recommendations(),
            'technical_details': self._generate_technical_details(),
            'timeline': self._generate_timeline()
        }
    
    def _generate_metadata(self) -> Dict:
        return {
            'scan_id': self.scan_data.get('scan_id', ''),
            'target_url': self.scan_data.get('target_url', ''),
            'scan_date': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'scan_duration': self.scan_data.get('duration', 0),
            'scanner_version': '1.0.0',
            'scan_type': 'comprehensive'
        }
    
    def _generate_executive_summary(self) -> Dict:
        risk_assessment = self.scan_data.get('risk_assessment', {})
        findings = self.scan_data.get('validated_results', [])
        
        critical = risk_assessment.get('critical_count', 0)
        high = risk_assessment.get('high_count', 0)
        
        if critical > 0:
            summary_text = f"The security assessment identified {critical} critical and {high} high-severity vulnerabilities that require immediate attention. Your application is at significant risk and should not be deployed to production until these issues are resolved."
        elif high > 0:
            summary_text = f"The assessment found {high} high-severity vulnerabilities that should be addressed before deployment. While no critical issues were detected, these vulnerabilities pose serious security risks."
        elif risk_assessment.get('medium_count', 0) > 0:
            summary_text = f"The scan identified {risk_assessment.get('medium_count', 0)} medium-severity issues. While not immediately critical, these should be addressed to improve your security posture."
        else:
            summary_text = "Congratulations! No significant vulnerabilities were detected. Your application demonstrates good security practices. Continue regular security assessments to maintain this level of security."
        
        return {
            'overall_risk': risk_assessment.get('risk_level', 'unknown'),
            'security_score': risk_assessment.get('overall_score', 0),
            'summary': summary_text,
            'total_issues': len(findings),
            'pages_scanned': len(self.scan_data.get('crawl_data', {}).get('pages', [])),
            'technologies_detected': self.scan_data.get('crawl_data', {}).get('technologies', [])
        }
    
    def _organize_findings(self) -> List[Dict]:
        findings = self.scan_data.get('validated_results', [])
        
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_findings = sorted(
            findings,
            key=lambda x: (severity_order.get(x['severity'], 4), -x['confidence'])
        )
        
        organized = []
        for idx, finding in enumerate(sorted_findings, 1):
            organized.append({
                'id': f"VULN-{idx:03d}",
                'title': finding['vulnerability_type'],
                'severity': finding['severity'],
                'confidence': round(finding['confidence'] * 100, 1),
                'url': finding['url'],
                'cvss_score': finding.get('cvss_score', 0),
                'cwe': finding.get('cwe', 'N/A'),
                'description': self._generate_finding_description(finding),
                'impact': self._generate_impact_description(finding),
                'remediation': finding.get('remediation', {}),
                'technical_details': finding.get('details', {})
            })
        
        return organized
    
    def _generate_finding_description(self, finding: Dict) -> str:
        vuln_type = finding['vulnerability_type']
        
        descriptions = {
            'SQL Injection': f"A SQL injection vulnerability was discovered at {finding['url']}. This allows attackers to manipulate database queries by injecting malicious SQL code through user input fields.",
            
            'XSS': f"A cross-site scripting (XSS) vulnerability was found at {finding['url']}. Attackers can inject malicious scripts that execute in users' browsers, potentially stealing sensitive information.",
            
            'Security Misconfiguration': f"Security headers are missing or misconfigured at {finding['url']}. This exposes the application to various attacks including clickjacking, MIME-sniffing, and protocol downgrade attacks."
        }
        
        for key in descriptions:
            if key.lower() in vuln_type.lower():
                return descriptions[key]
        
        return f"A {vuln_type} vulnerability was detected at {finding['url']}."
    
    def _generate_impact_description(self, finding: Dict) -> str:
        vuln_type = finding['vulnerability_type']
        severity = finding['severity']
        
        if 'sql injection' in vuln_type.lower():
            if severity == 'critical':
                return "Critical Impact: Attackers can read, modify, or delete database contents, potentially compromising all user data, administrative credentials, and business-critical information. Complete database takeover is possible."
            else:
                return "High Impact: Attackers may be able to extract sensitive information from the database or modify certain data records."
        
        elif 'xss' in vuln_type.lower():
            if 'stored' in vuln_type.lower():
                return "High Impact: Stored XSS can affect all users who view the compromised page. Attackers can steal session cookies, redirect users to malicious sites, or modify page content for all visitors."
            else:
                return "Medium Impact: Attackers can execute scripts in the context of individual users who click malicious links, potentially stealing their session data or credentials."
        
        elif 'security misconfiguration' in vuln_type.lower():
            return "Medium Impact: Missing security headers leave the application vulnerable to various client-side attacks including clickjacking, MIME-type confusion, and protocol downgrade attacks."
        
        return "The impact depends on how this vulnerability is exploited and what data is accessible."
    
    def _generate_recommendations(self) -> List[Dict]:
        findings = self.scan_data.get('validated_results', [])
        
        critical_count = sum(1 for f in findings if f['severity'] == 'critical')
        high_count = sum(1 for f in findings if f['severity'] == 'high')
        
        recommendations = []
        
        if critical_count > 0:
            recommendations.append({
                'priority': 'immediate',
                'title': 'Address Critical Vulnerabilities',
                'description': f'Fix all {critical_count} critical vulnerabilities before deploying to production.',
                'effort': 'High',
                'impact': 'Critical'
            })
        
        if high_count > 0:
            recommendations.append({
                'priority': 'high',
                'title': 'Remediate High-Severity Issues',
                'description': f'Address {high_count} high-severity vulnerabilities within the next sprint.',
                'effort': 'Medium',
                'impact': 'High'
            })
        
        recommendations.extend([
            {
                'priority': 'medium',
                'title': 'Implement Secure Development Practices',
                'description': 'Integrate security testing into your CI/CD pipeline and conduct regular code reviews.',
                'effort': 'Medium',
                'impact': 'High'
            },
            {
                'priority': 'medium',
                'title': 'Security Training',
                'description': 'Provide OWASP Top 10 security training for all developers.',
                'effort': 'Low',
                'impact': 'Medium'
            },
            {
                'priority': 'low',
                'title': 'Regular Security Assessments',
                'description': 'Schedule quarterly security scans to catch new vulnerabilities early.',
                'effort': 'Low',
                'impact': 'Medium'
            }
        ])
        
        return recommendations
    
    def _generate_technical_details(self) -> Dict:
        crawl_data = self.scan_data.get('crawl_data', {})
        
        return {
            'pages_analyzed': len(crawl_data.get('pages', [])),
            'forms_found': len(crawl_data.get('forms', [])),
            'inputs_analyzed': len(crawl_data.get('inputs', [])),
            'technologies': crawl_data.get('technologies', []),
            'security_headers': crawl_data.get('headers', {}),
            'ml_model_version': 'CodeBERT-v1.0',
            'tools_used': ['SQLmap', 'XSStrike', 'Custom Analyzers']
        }
    
    def _generate_timeline(self) -> List[Dict]:
        return [
            {
                'phase': 'Reconnaissance',
                'duration': '5 seconds',
                'description': 'Web crawling and data collection'
            },
            {
                'phase': 'ML Analysis',
                'duration': '3 seconds',
                'description': 'AI-powered vulnerability prediction'
            },
            {
                'phase': 'Active Testing',
                'duration': '15-20 seconds',
                'description': 'Targeted vulnerability verification'
            },
            {
                'phase': 'Validation',
                'duration': '2 seconds',
                'description': 'Cross-validation and confidence scoring'
            },
            {
                'phase': 'Reporting',
                'duration': '5 seconds',
                'description': 'Report generation and formatting'
            }
        ]
    
    def export_json(self) -> str:
        report = self.generate()
        return json.dumps(report, indent=2)
    
    def export_summary(self) -> str:
        report = self.generate()
        summary = report['executive_summary']
        
        text = f"""
SECURITY ASSESSMENT SUMMARY
{'='*60}

Target: {report['metadata']['target_url']}
Scan Date: {report['metadata']['scan_date']}
Security Score: {summary['security_score']}/100
Risk Level: {summary['overall_risk'].upper()}

{summary['summary']}

FINDINGS SUMMARY:
- Critical: {report['executive_summary'].get('critical_count', 0)}
- High: {report['executive_summary'].get('high_count', 0)}
- Medium: {report['executive_summary'].get('medium_count', 0)}
- Low: {report['executive_summary'].get('low_count', 0)}

Total Issues Found: {summary['total_issues']}
Pages Scanned: {summary['pages_scanned']}
        """
        
        return text.strip()
    
print("CLASS EXISTS:", 'ReportGenerator' in globals())