print("VALIDATOR FILE LOADED")
from typing import Dict, List
import statistics

class ResultValidator:
    def __init__(self):
        self.validation_rules = {
            'sql_injection': self._validate_sql_injection,
            'xss': self._validate_xss,
            'security_misconfiguration': self._validate_security_headers
        }
    
    def validate_results(self, ml_results: Dict, active_results: List[Dict]) -> List[Dict]:
        validated = []
        
        for active_result in active_results:
            vuln_type = active_result['vulnerability_type'].lower()
            
            ml_confidence = self._get_ml_confidence(ml_results, active_result['url'], vuln_type)
            active_confidence = active_result['confidence']
            
            validation_result = self._cross_validate(
                vuln_type,
                ml_confidence,
                active_confidence,
                active_result
            )
            
            if validation_result['is_valid']:
                validated_result = active_result.copy()
                validated_result['confidence'] = validation_result['final_confidence']
                validated_result['validation_score'] = validation_result['score']
                validated.append(validated_result)
        
        return validated
    
    def _get_ml_confidence(self, ml_results: Dict, url: str, vuln_type: str) -> float:
        url_predictions = ml_results.get(url, {})
        
        vuln_mapping = {
            'sql injection': 'sql_injection',
            'xss': 'xss',
            'security misconfiguration': 'security_misconfiguration'
        }
        
        mapped_type = vuln_mapping.get(vuln_type.lower(), vuln_type.replace(' ', '_').lower())
        
        return url_predictions.get(mapped_type, {}).get('confidence', 0.0)
    
    def _cross_validate(self, vuln_type: str, ml_conf: float, active_conf: float, result: Dict) -> Dict:
        base_type = vuln_type.split('(')[0].strip().lower()
        
        if ml_conf > 0.75 and active_conf > 0.80:
            final_confidence = (ml_conf * 0.4) + (active_conf * 0.6)
            final_confidence = min(final_confidence * 1.2, 0.98)
            score = 95
            is_valid = True
            
        elif ml_conf > 0.6 and active_conf > 0.70:
            final_confidence = (ml_conf * 0.45) + (active_conf * 0.55)
            final_confidence = min(final_confidence * 1.1, 0.95)
            score = 85
            is_valid = True
            
        elif ml_conf > 0.5 or active_conf > 0.75:
            final_confidence = (ml_conf * 0.5) + (active_conf * 0.5)
            score = 75
            is_valid = True
            
        else:
            final_confidence = active_conf
            score = 60
            is_valid = active_conf > 0.6
        
        if base_type in self.validation_rules:
            additional_validation = self.validation_rules[base_type](result)
            if additional_validation['boost']:
                final_confidence = min(final_confidence * 1.1, 0.99)
                score = min(score + 5, 100)
        
        return {
            'is_valid': is_valid,
            'final_confidence': final_confidence,
            'score': score,
            'ml_contribution': ml_conf,
            'active_contribution': active_conf
        }
    
    def _validate_sql_injection(self, result: Dict) -> Dict:
        details = result.get('details', {})
        
        boost = False
        if details.get('database') and details.get('database') != 'unknown':
            boost = True
        
        if details.get('injection_type') in ['UNION query', 'error-based']:
            boost = True
        
        return {'boost': boost}
    
    def _validate_xss(self, result: Dict) -> Dict:
        details = result.get('details', {})
        
        boost = False
        if details.get('context') and details.get('context') != 'unknown':
            boost = True
        
        if details.get('payload'):
            boost = True
        
        return {'boost': boost}
    
    def _validate_security_headers(self, result: Dict) -> Dict:
        details = result.get('details', {})
        score = details.get('score', 100)
        
        boost = score < 50
        
        return {'boost': boost}
    
    def calculate_overall_risk(self, validated_results: List[Dict]) -> Dict:
        if not validated_results:
            return {
                'overall_score': 100,
                'risk_level': 'safe',
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0
            }
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2}
        
        total_weight = 0
        
        for result in validated_results:
            severity = result['severity']
            severity_counts[severity] += 1
            total_weight += severity_weights[severity]
        
        max_possible_weight = len(validated_results) * 10
        overall_score = max(0, 100 - (total_weight / max_possible_weight * 100))
        
        if overall_score >= 80:
            risk_level = 'low'
        elif overall_score >= 60:
            risk_level = 'medium'
        elif overall_score >= 40:
            risk_level = 'high'
        else:
            risk_level = 'critical'
        
        return {
            'overall_score': round(overall_score, 1),
            'risk_level': risk_level,
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'medium_count': severity_counts['medium'],
            'low_count': severity_counts['low'],
            'total_vulnerabilities': len(validated_results)
        }
    

print("CLASS EXISTS:", "ResultValidator" in globals())