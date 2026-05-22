import subprocess
import os
import re
import sys
from typing import Dict
from pathlib import Path


class SQLMapWrapper:
    def __init__(self, target_url: str, data: Dict = None):
        self.target_url = target_url
        self.data = data
        self.sqlmap_path = self._find_sqlmap()

    def _find_sqlmap(self):
        possible_paths = [
            'tools/sqlmap/sqlmap.py',
            'tools\\sqlmap\\sqlmap.py',
            Path(__file__).parent.parent / 'tools' / 'sqlmap' / 'sqlmap.py'
        ]

        for path in possible_paths:
            path = Path(path)
            if path.exists():
                return str(path.absolute())

        return None   # graceful fallback

    def scan(self, level: int = 2, risk: int = 1, timeout: int = 120) -> Dict:

        if not self.sqlmap_path:
            return {
                'vulnerable': False,
                'details': {},
                'confidence': 0.0,
                'severity': 'skipped',
                'raw_output': 'SQLmap not available in hosted environment'
            }

        cmd = [
            sys.executable,
            self.sqlmap_path,
            '-u', self.target_url,
            '--batch',
            '--level', str(level),
            '--risk', str(risk),
            '--threads', '2',
            '--timeout', '20',
            '--retries', '1',
            '--technique', 'BEUST',
            '--random-agent',
            '--skip-waf'
        ]

        if self.data:
            data_str = '&'.join([f"{k}={v}" for k, v in self.data.items()])
            cmd.extend(['--data', data_str])

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.path.dirname(self.sqlmap_path)
            )

            stdout, stderr = process.communicate(timeout=timeout)
            return self._parse_output(stdout)

        except Exception:
            return {
                'vulnerable': False,
                'details': {},
                'confidence': 0.0,
                'severity': 'skipped',
                'raw_output': 'SQLmap execution skipped'
            }

    def _parse_output(self, output: str) -> Dict:
        vulnerable = False
        details = {}
        confidence = 0.0

        vuln_patterns = [
            r'Parameter.*?appears to be.*?injectable',
            r'is vulnerable',
            r'sqlmap identified the following injection',
            r'Type:.*?(boolean-based|time-based|error-based|UNION|stacked)'
        ]

        for pattern in vuln_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                vulnerable = True
                break

        if vulnerable:
            type_match = re.search(r'Type:\s*([^\n]+)', output)
            if type_match:
                details['injection_type'] = type_match.group(1).strip()

            db_match = re.search(r'back-end DBMS:\s*([^\n]+)', output)
            if db_match:
                details['database'] = db_match.group(1).strip()

            payload_match = re.search(r'Payload:\s*([^\n]+)', output)
            if payload_match:
                details['payload'] = payload_match.group(1).strip()

            param_match = re.search(r'Parameter:\s*(\w+)', output)
            if param_match:
                details['parameter'] = param_match.group(1)

            confidence = 0.95

        return {
            'vulnerable': vulnerable,
            'details': details,
            'confidence': confidence,
            'severity': 'critical' if vulnerable else 'safe',
            'raw_output': output[:500]
        }