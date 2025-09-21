"""
Code Analyzer Service - Analyze code quality, complexity, and patterns
"""

import ast
import logging
from typing import Dict, List, Any, Optional
import re
from collections import defaultdict
import subprocess
import tempfile
import os

logger = logging.getLogger(__name__)

class CodeAnalyzer:
    def __init__(self):
        self.complexity_threshold = 10
        self.line_length_threshold = 120
        self.function_length_threshold = 50
    
    async def analyze_code(self, files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze code quality across all files"""
        analysis_results = {
            'overall_score': 0,
            'total_files': len(files),
            'analyzed_files': 0,
            'issues': [],
            'metrics': {
                'complexity': 0,
                'maintainability': 0,
                'test_coverage': 0,
                'code_duplication': 0
            },
            'file_analyses': []
        }
        
        python_files = [f for f in files if f['filename'].endswith('.py')]
        analysis_results['analyzed_files'] = len(python_files)
        
        total_complexity = 0
        total_issues = 0
        
        for file_data in python_files:
            if file_data.get('content'):
                file_analysis = await self._analyze_python_file(file_data)
                analysis_results['file_analyses'].append(file_analysis)
                
                total_complexity += file_analysis.get('complexity', 0)
                total_issues += len(file_analysis.get('issues', []))
                analysis_results['issues'].extend(file_analysis.get('issues', []))
        
        # Calculate overall metrics
        if python_files:
            analysis_results['metrics']['complexity'] = total_complexity / len(python_files)
            analysis_results['overall_score'] = self._calculate_overall_score(analysis_results)
        
        return analysis_results
    
    async def _analyze_python_file(self, file_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual Python file"""
        filename = file_data['filename']
        content = file_data['content']
        
        if not content:
            return {'filename': filename, 'issues': [], 'complexity': 0}
        
        analysis = {
            'filename': filename,
            'complexity': 0,
            'issues': [],
            'metrics': {
                'lines_of_code': len(content.split('\n')),
                'functions': 0,
                'classes': 0,
                'imports': 0
            },
            'quality_score': 0
        }
        
        try:
            tree = ast.parse(content)
            
            # AST-based analysis
            visitor = PythonAnalysisVisitor()
            visitor.visit(tree)
            
            analysis['complexity'] = visitor.complexity
            analysis['metrics']['functions'] = visitor.function_count
            analysis['metrics']['classes'] = visitor.class_count
            analysis['metrics']['imports'] = visitor.import_count
            
            # Code quality checks
            analysis['issues'].extend(await self._check_code_quality(content, filename))
            
            # Function complexity issues
            for func_name, func_complexity in visitor.function_complexities.items():
                if func_complexity > self.complexity_threshold:
                    analysis['issues'].append({
                        'type': 'complexity',
                        'severity': 'warning',
                        'message': f"Function '{func_name}' has high complexity ({func_complexity})",
                        'line': visitor.function_lines.get(func_name, 1),
                        'suggestion': "Consider breaking this function into smaller pieces"
                    })
            
            # Long function issues
            for func_name, func_length in visitor.function_lengths.items():
                if func_length > self.function_length_threshold:
                    analysis['issues'].append({
                        'type': 'maintainability',
                        'severity': 'info',
                        'message': f"Function '{func_name}' is very long ({func_length} lines)",
                        'line': visitor.function_lines.get(func_name, 1),
                        'suggestion': "Consider splitting long functions for better readability"
                    })
            
            analysis['quality_score'] = self._calculate_file_quality_score(analysis)
            
        except SyntaxError as e:
            analysis['issues'].append({
                'type': 'syntax',
                'severity': 'error',
                'message': f"Syntax error: {e.msg}",
                'line': e.lineno or 1,
                'suggestion': "Fix syntax error before proceeding"
            })
        except Exception as e:
            logger.error(f"Error analyzing {filename}: {e}")
            analysis['issues'].append({
                'type': 'analysis',
                'severity': 'error',
                'message': f"Analysis failed: {str(e)}",
                'line': 1,
                'suggestion': "Check file format and content"
            })
        
        return analysis
    
    async def _check_code_quality(self, content: str, filename: str) -> List[Dict[str, Any]]:
        """Check various code quality metrics"""
        issues = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Line length check
            if len(line) > self.line_length_threshold:
                issues.append({
                    'type': 'style',
                    'severity': 'info',
                    'message': f"Line too long ({len(line)} > {self.line_length_threshold})",
                    'line': i,
                    'suggestion': "Consider breaking long lines for better readability"
                })
            
            # TODO comments
            if 'TODO' in line or 'FIXME' in line or 'HACK' in line:
                issues.append({
                    'type': 'maintainability',
                    'severity': 'info',
                    'message': "TODO/FIXME comment found",
                    'line': i,
                    'suggestion': "Consider addressing TODO items before merging"
                })
            
            # Potential security issues
            if re.search(r'eval\s*\(|exec\s*\(', line):
                issues.append({
                    'type': 'security',
                    'severity': 'warning',
                    'message': "Use of eval() or exec() detected",
                    'line': i,
                    'suggestion': "Avoid eval() and exec() for security reasons"
                })
            
            # SQL injection potential
            if re.search(r'(SELECT|INSERT|UPDATE|DELETE).*%s|.*\+.*[\'"]', line, re.IGNORECASE):
                issues.append({
                    'type': 'security',
                    'severity': 'warning',
                    'message': "Potential SQL injection vulnerability",
                    'line': i,
                    'suggestion': "Use parameterized queries to prevent SQL injection"
                })
        
        return issues
    
    def _calculate_file_quality_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate quality score for a file (0-100)"""
        base_score = 100.0
        
        # Deduct points for issues
        for issue in analysis['issues']:
            if issue['severity'] == 'error':
                base_score -= 20
            elif issue['severity'] == 'warning':
                base_score -= 10
            elif issue['severity'] == 'info':
                base_score -= 5
        
        # Deduct points for high complexity
        if analysis['complexity'] > self.complexity_threshold:
            base_score -= (analysis['complexity'] - self.complexity_threshold) * 2
        
        return max(0, min(100, base_score))
    
    def _calculate_overall_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall project quality score"""
        if not analysis['file_analyses']:
            return 0
        
        file_scores = [fa.get('quality_score', 0) for fa in analysis['file_analyses']]
        avg_score = sum(file_scores) / len(file_scores) if file_scores else 0
        
        # Adjust for overall project factors
        total_issues = len(analysis['issues'])
        if total_issues > 50:
            avg_score *= 0.8
        elif total_issues > 20:
            avg_score *= 0.9
        
        return round(avg_score, 1)

class PythonAnalysisVisitor(ast.NodeVisitor):
    """AST visitor for Python code analysis"""
    
    def __init__(self):
        self.complexity = 0
        self.function_count = 0
        self.class_count = 0
        self.import_count = 0
        self.function_complexities = {}
        self.function_lengths = {}
        self.function_lines = {}
        self.current_function = None
        self.current_function_start = 0
    
    def visit_FunctionDef(self, node):
        """Analyze function definitions"""
        self.function_count += 1
        self.current_function = node.name
        self.current_function_start = node.lineno
        self.function_lines[node.name] = node.lineno
        
        # Calculate function complexity
        func_complexity = self._calculate_function_complexity(node)
        self.function_complexities[node.name] = func_complexity
        self.complexity += func_complexity
        
        # Calculate function length
        func_length = self._calculate_function_length(node)
        self.function_lengths[node.name] = func_length
        
        self.generic_visit(node)
        self.current_function = None
    
    def visit_AsyncFunctionDef(self, node):
        """Analyze async function definitions"""
        self.visit_FunctionDef(node)
    
    def visit_ClassDef(self, node):
        """Analyze class definitions"""
        self.class_count += 1
        self.generic_visit(node)
    
    def visit_Import(self, node):
        """Analyze import statements"""
        self.import_count += len(node.names)
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """Analyze from-import statements"""
        if node.names:
            self.import_count += len(node.names)
        self.generic_visit(node)
    
    def _calculate_function_complexity(self, node) -> int:
        """Calculate cyclomatic complexity of a function"""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, (ast.And, ast.Or)):
                complexity += 1
            elif isinstance(child, ast.comprehension):
                complexity += 1
        
        return complexity
    
    def _calculate_function_length(self, node) -> int:
        """Calculate function length in lines"""
        if hasattr(node, 'end_lineno') and node.end_lineno:
            return node.end_lineno - node.lineno + 1
        else:
            # Fallback: count child nodes
            return len([n for n in ast.walk(node) if isinstance(n, ast.stmt)])