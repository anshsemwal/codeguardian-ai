"""
Security Scanner Service - Detect security vulnerabilities in code
"""

import logging
import subprocess
import tempfile
import os
import json
import re
from typing import Dict, List, Any
import ast

logger = logging.getLogger(__name__)

class SecurityScanner:
    def __init__(self):
        self.severity_levels = {
            'HIGH': 'error',
            'MEDIUM': 'warning', 
            'LOW': 'info'
        }
        
        # Security patterns to detect
        self.security_patterns = {
            'sql_injection': [
                r'(SELECT|INSERT|UPDATE|DELETE).*%s',
                r'(SELECT|INSERT|UPDATE|DELETE).*\+.*[\'"]',
                r'cursor\.execute.*%.*[\'"]',
                r'\.format\(.*sql.*\)',
            ],
            'command_injection': [
                r'os\.system\(',
                r'subprocess\.(call|check_call|check_output|run|Popen).*shell=True',
                r'commands\.getstatusoutput',
                r'os\.popen\(',
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*[\'"][^\'"]+[\'"]',
                r'api_key\s*=\s*[\'"][^\'"]+[\'"]',
                r'secret\s*=\s*[\'"][^\'"]+[\'"]',
                r'token\s*=\s*[\'"][^\'"]+[\'"]',
                r'(aws_access_key|aws_secret_key)\s*=\s*[\'"][^\'"]+[\'"]',
            ],
            'unsafe_deserialization': [
                r'pickle\.loads?\(',
                r'cPickle\.loads?\(',
                r'yaml\.load\(',
                r'eval\s*\(',
                r'exec\s*\(',
            ],
            'weak_crypto': [
                r'md5\s*\(',
                r'sha1\s*\(',
                r'DES\.',
                r'RC4\.',
                r'random\.random\(',
            ],
            'path_traversal': [
                r'open\s*\([^)]*\.\.[^)]*\)',
                r'file\s*\([^)]*\.\.[^)]*\)',
                r'os\.path\.join.*\.\.',
            ]
        }
    
    async def scan_files(self, files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Scan files for security vulnerabilities"""
        scan_results = {
            'total_files': len(files),
            'scanned_files': 0,
            'vulnerabilities': [],
            'security_score': 100,
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'recommendations': []
        }
        
        python_files = [f for f in files if f['filename'].endswith('.py')]
        scan_results['scanned_files'] = len(python_files)
        
        for file_data in python_files:
            if file_data.get('content'):
                file_vulns = await self._scan_python_file(file_data)
                scan_results['vulnerabilities'].extend(file_vulns)
        
        # Calculate security score and summary
        scan_results = self._calculate_security_metrics(scan_results)
        scan_results['recommendations'] = self._generate_security_recommendations(scan_results)
        
        return scan_results
    
    async def _scan_python_file(self, file_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan individual Python file for vulnerabilities"""
        filename = file_data['filename']
        content = file_data['content']
        vulnerabilities = []
        
        if not content:
            return vulnerabilities
        
        lines = content.split('\n')
        
        # Pattern-based scanning
        for i, line in enumerate(lines, 1):
            line_vulns = self._scan_line_patterns(line, i, filename)
            vulnerabilities.extend(line_vulns)
        
        # AST-based scanning for more complex patterns
        try:
            tree = ast.parse(content)
            ast_vulns = self._scan_ast_patterns(tree, filename)
            vulnerabilities.extend(ast_vulns)
        except SyntaxError:
            pass  # Skip files with syntax errors
        
        # Try Bandit if available
        bandit_vulns = await self._run_bandit_scan(content, filename)
        vulnerabilities.extend(bandit_vulns)
        
        return vulnerabilities
    
    def _scan_line_patterns(self, line: str, line_number: int, filename: str) -> List[Dict[str, Any]]:
        """Scan line for security patterns"""
        vulnerabilities = []
        
        for vuln_type, patterns in self.security_patterns.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    severity = self._determine_severity(vuln_type, line)
                    
                    vulnerabilities.append({
                        'type': 'security',
                        'category': vuln_type,
                        'severity': severity,
                        'message': self._get_vulnerability_message(vuln_type),
                        'line': line_number,
                        'filename': filename,
                        'code_snippet': line.strip(),
                        'suggestion': self._get_vulnerability_suggestion(vuln_type),
                        'cwe_id': self._get_cwe_id(vuln_type)
                    })
        
        return vulnerabilities
    
    def _scan_ast_patterns(self, tree: ast.AST, filename: str) -> List[Dict[str, Any]]:
        """Scan AST for complex security patterns"""
        vulnerabilities = []
        
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    
                    # Check for eval/exec usage
                    if func_name in ['eval', 'exec']:
                        vulnerabilities.append({
                            'type': 'security',
                            'category': 'code_injection',
                            'severity': 'error',
                            'message': f"Use of {func_name}() is dangerous",
                            'line': node.lineno,
                            'filename': filename,
                            'suggestion': f"Avoid using {func_name}() as it can execute arbitrary code",
                            'cwe_id': 'CWE-94'
                        })
                
                # Check for subprocess with shell=True
                elif isinstance(node.func, ast.Attribute):
                    if (hasattr(node.func, 'attr') and 
                        node.func.attr in ['call', 'check_call', 'run', 'Popen']):
                        
                        for keyword in node.keywords:
                            if (keyword.arg == 'shell' and 
                                isinstance(keyword.value, ast.Constant) and 
                                keyword.value.value is True):
                                
                                vulnerabilities.append({
                                    'type': 'security',
                                    'category': 'command_injection',
                                    'severity': 'warning',
                                    'message': "subprocess call with shell=True",
                                    'line': node.lineno,
                                    'filename': filename,
                                    'suggestion': "Use shell=False and pass command as list",
                                    'cwe_id': 'CWE-78'
                                })
            
            # Check for hardcoded strings that might be secrets
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(secret in var_name for secret in ['password', 'secret', 'key', 'token']):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                if len(node.value.value) > 5:  # Ignore short strings
                                    vulnerabilities.append({
                                        'type': 'security',
                                        'category': 'hardcoded_secrets',
                                        'severity': 'warning',
                                        'message': f"Possible hardcoded secret in variable '{target.id}'",
                                        'line': node.lineno,
                                        'filename': filename,
                                        'suggestion': "Use environment variables or secure credential storage",
                                        'cwe_id': 'CWE-798'
                                    })
        
        return vulnerabilities
    
    async def _run_bandit_scan(self, content: str, filename: str) -> List[Dict[str, Any]]:
        """Run Bandit security scanner if available"""
        vulnerabilities = []
        
        try:
            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name
            
            # Run bandit
            result = subprocess.run([
                'bandit', '-f', 'json', temp_file_path
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 or result.returncode == 1:  # 1 means issues found
                try:
                    bandit_output = json.loads(result.stdout)
                    for issue in bandit_output.get('results', []):
                        vulnerabilities.append({
                            'type': 'security',
                            'category': 'bandit_finding',
                            'severity': self.severity_levels.get(issue['issue_severity'], 'info'),
                            'message': issue['issue_text'],
                            'line': issue['line_number'],
                            'filename': filename,
                            'code_snippet': issue.get('code', ''),
                            'suggestion': f"Bandit {issue['test_id']}: {issue['issue_text']}",
                            'cwe_id': issue.get('cwe_id', 'CWE-000')
                        })
                except json.JSONDecodeError:
                    pass
            
            # Clean up
            os.unlink(temp_file_path)
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.debug(f"Bandit scan failed: {e}")
        
        return vulnerabilities
    
    def _determine_severity(self, vuln_type: str, code_line: str) -> str:
        """Determine vulnerability severity based on context"""
        severity_map = {
            'sql_injection': 'error',
            'command_injection': 'error',
            'hardcoded_secrets': 'warning',
            'unsafe_deserialization': 'error',
            'weak_crypto': 'warning',
            'path_traversal': 'warning'
        }
        return severity_map.get(vuln_type, 'info')
    
    def _get_vulnerability_message(self, vuln_type: str) -> str:
        """Get user-friendly vulnerability message"""
        messages = {
            'sql_injection': "Potential SQL injection vulnerability detected",
            'command_injection': "Potential command injection vulnerability detected", 
            'hardcoded_secrets': "Hardcoded secret or credential detected",
            'unsafe_deserialization': "Unsafe deserialization method detected",
            'weak_crypto': "Weak cryptographic method detected",
            'path_traversal': "Potential path traversal vulnerability detected"
        }
        return messages.get(vuln_type, "Security issue detected")
    
    def _get_vulnerability_suggestion(self, vuln_type: str) -> str:
        """Get security suggestion for vulnerability type"""
        suggestions = {
            'sql_injection': "Use parameterized queries or prepared statements",
            'command_injection': "Use subprocess with shell=False and validate input",
            'hardcoded_secrets': "Use environment variables or secure credential storage",
            'unsafe_deserialization': "Use safe serialization formats like JSON",
            'weak_crypto': "Use strong cryptographic algorithms like SHA-256 or bcrypt",
            'path_traversal': "Validate and sanitize file paths, use os.path.abspath()"
        }
        return suggestions.get(vuln_type, "Review code for security best practices")
    
    def _get_cwe_id(self, vuln_type: str) -> str:
        """Get CWE ID for vulnerability type"""
        cwe_map = {
            'sql_injection': 'CWE-89',
            'command_injection': 'CWE-78',
            'hardcoded_secrets': 'CWE-798',
            'unsafe_deserialization': 'CWE-502',
            'weak_crypto': 'CWE-327',
            'path_traversal': 'CWE-22'
        }
        return cwe_map.get(vuln_type, 'CWE-000')
    
    def _calculate_security_metrics(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate security metrics and scores"""
        vulnerabilities = scan_results['vulnerabilities']
        summary = scan_results['summary']
        
        for vuln in vulnerabilities:
            if vuln['severity'] == 'error':
                if vuln['category'] in ['sql_injection', 'command_injection', 'unsafe_deserialization']:
                    summary['critical'] += 1
                else:
                    summary['high'] += 1
            elif vuln['severity'] == 'warning':
                summary['medium'] += 1
            else:
                summary['low'] += 1
        
        # Calculate security score (0-100)
        base_score = 100
        base_score -= summary['critical'] * 25
        base_score -= summary['high'] * 15
        base_score -= summary['medium'] * 8
        base_score -= summary['low'] * 3
        
        scan_results['security_score'] = max(0, base_score)
        
        return scan_results
    
    def _generate_security_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on scan results"""
        recommendations = []
        summary = scan_results['summary']
        
        if summary['critical'] > 0:
            recommendations.append("🚨 Critical vulnerabilities found! Address immediately before deployment.")
        
        if summary['high'] > 0:
            recommendations.append("⚠️  High-severity issues detected. Review and fix before merging.")
        
        if summary['medium'] > 0:
            recommendations.append("📋 Medium-severity issues found. Consider addressing in this PR.")
        
        if summary['low'] > 0:
            recommendations.append("💡 Low-severity issues detected. Good to address for security best practices.")
        
        # General recommendations
        vulnerabilities = scan_results['vulnerabilities']
        vuln_categories = set(v['category'] for v in vulnerabilities)
        
        if 'sql_injection' in vuln_categories:
            recommendations.append("🛡️  Use ORM or parameterized queries to prevent SQL injection.")
        
        if 'hardcoded_secrets' in vuln_categories:
            recommendations.append("🔐 Move secrets to environment variables or secure credential management.")
        
        if 'command_injection' in vuln_categories:
            recommendations.append("⚡ Validate input and avoid shell=True in subprocess calls.")
        
        if not vulnerabilities:
            recommendations.append("✅ No security vulnerabilities detected! Great job!")
        
        return recommendations