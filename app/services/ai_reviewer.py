"""
AI Reviewer Service - Generate intelligent code review suggestions
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional
import re
import json

logger = logging.getLogger(__name__)

class AIReviewer:
    def __init__(self):
        self.confidence_threshold = 0.7
        self.max_suggestion_length = 200
        
        # Code review patterns and suggestions
        self.review_patterns = {
            'naming_conventions': {
                'patterns': [
                    r'def [a-z]+[A-Z]',  # camelCase functions
                    r'class [a-z]',      # lowercase class names
                    r'[A-Z_]{2,} = ',    # potential constants not in caps
                ],
                'suggestions': [
                    "Use snake_case for function names (PEP 8)",
                    "Use PascalCase for class names (PEP 8)",
                    "Use UPPER_CASE for constants (PEP 8)"
                ]
            },
            'error_handling': {
                'patterns': [
                    r'except:',
                    r'except Exception:',
                    r'pass\s*$',
                ],
                'suggestions': [
                    "Catch specific exceptions instead of bare except",
                    "Consider catching more specific exceptions",
                    "Avoid empty except blocks, at least log the error"
                ]
            },
            'performance': {
                'patterns': [
                    r'for.*in.*range\(len\(',
                    r'\+\s*=.*str',
                    r'.*\.append\(.*\)\s*$',
                ],
                'suggestions': [
                    "Consider using enumerate() instead of range(len())",
                    "Use join() for string concatenation in loops",
                    "Consider list comprehension for better performance"
                ]
            },
            'code_style': {
                'patterns': [
                    r'==\s*(True|False)',
                    r'!=\s*(True|False)',
                    r'if.*==.*None',
                    r'if.*!=.*None',
                ],
                'suggestions': [
                    "Use 'if condition:' instead of '== True'",
                    "Use 'if not condition:' instead of '== False'", 
                    "Use 'if var is None:' instead of '== None'",
                    "Use 'if var is not None:' instead of '!= None'"
                ]
            }
        }
    
    async def review_code_changes(self, pr_data: Dict[str, Any], 
                                code_analysis: Dict[str, Any],
                                security_scan: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-powered code review"""
        
        review_result = {
            'overall_recommendation': 'COMMENT',  # APPROVE, REQUEST_CHANGES, COMMENT
            'confidence_score': 0.0,
            'summary': '',
            'suggestions': [],
            'inline_comments': [],
            'praise_points': [],
            'improvement_areas': []
        }
        
        # Analyze PR metadata
        pr_analysis = self._analyze_pr_metadata(pr_data)
        
        # Generate suggestions based on code analysis
        code_suggestions = await self._generate_code_suggestions(code_analysis)
        
        # Generate security-focused suggestions
        security_suggestions = await self._generate_security_suggestions(security_scan)
        
        # Generate style and best practice suggestions
        style_suggestions = await self._generate_style_suggestions(pr_data)
        
        # Combine all suggestions
        all_suggestions = code_suggestions + security_suggestions + style_suggestions
        review_result['suggestions'] = all_suggestions
        
        # Generate overall assessment
        review_result = await self._generate_overall_assessment(
            review_result, pr_data, code_analysis, security_scan
        )
        
        # Generate inline comments for specific issues
        review_result['inline_comments'] = await self._generate_inline_comments(
            pr_data, code_analysis, security_scan
        )
        
        return review_result
    
    def _analyze_pr_metadata(self, pr_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze PR metadata for insights"""
        analysis = {
            'size_category': 'small',
            'complexity_indicator': 'low',
            'description_quality': 'good'
        }
        
        # Categorize PR size
        changes = pr_data.get('additions', 0) + pr_data.get('deletions', 0)
        if changes > 500:
            analysis['size_category'] = 'large'
        elif changes > 100:
            analysis['size_category'] = 'medium'
        
        # Check description quality
        description = pr_data.get('description', '').strip()
        if len(description) < 20:
            analysis['description_quality'] = 'poor'
        elif len(description) < 50:
            analysis['description_quality'] = 'fair'
        
        # Files changed indicator
        files_changed = pr_data.get('changed_files', 0)
        if files_changed > 20:
            analysis['complexity_indicator'] = 'high'
        elif files_changed > 5:
            analysis['complexity_indicator'] = 'medium'
        
        return analysis
    
    async def _generate_code_suggestions(self, code_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate suggestions based on code analysis"""
        suggestions = []
        
        overall_score = code_analysis.get('overall_score', 100)
        complexity = code_analysis.get('metrics', {}).get('complexity', 0)
        
        if overall_score < 70:
            suggestions.append({
                'type': 'improvement',
                'priority': 'high',
                'title': 'Code Quality Improvement Needed',
                'description': f"Overall code quality score is {overall_score}/100. Consider addressing the identified issues.",
                'confidence': 0.9
            })
        
        if complexity > 8:
            suggestions.append({
                'type': 'refactoring',
                'priority': 'medium', 
                'title': 'High Code Complexity Detected',
                'description': f"Average complexity is {complexity:.1f}. Consider breaking down complex functions.",
                'confidence': 0.8
            })
        
        # Analyze specific issues
        issues = code_analysis.get('issues', [])
        error_count = sum(1 for issue in issues if issue.get('severity') == 'error')
        warning_count = sum(1 for issue in issues if issue.get('severity') == 'warning')
        
        if error_count > 0:
            suggestions.append({
                'type': 'bug_fix',
                'priority': 'high',
                'title': 'Critical Issues Found',
                'description': f"Found {error_count} critical issues that need immediate attention.",
                'confidence': 0.95
            })
        
        if warning_count > 5:
            suggestions.append({
                'type': 'cleanup',
                'priority': 'medium',
                'title': 'Multiple Warnings Detected', 
                'description': f"Found {warning_count} warnings. Consider addressing them for better code quality.",
                'confidence': 0.7
            })
        
        return suggestions
    
    async def _generate_security_suggestions(self, security_scan: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security-focused suggestions"""
        suggestions = []
        
        security_score = security_scan.get('security_score', 100)
        summary = security_scan.get('summary', {})
        
        if summary.get('critical', 0) > 0:
            suggestions.append({
                'type': 'security',
                'priority': 'critical',
                'title': 'Critical Security Vulnerabilities',
                'description': f"Found {summary['critical']} critical security issues. Must be fixed before merging!",
                'confidence': 0.95
            })
        
        if summary.get('high', 0) > 0:
            suggestions.append({
                'type': 'security',
                'priority': 'high',
                'title': 'High-Severity Security Issues',
                'description': f"Found {summary['high']} high-severity security issues. Strongly recommend fixing.",
                'confidence': 0.9
            })
        
        if security_score < 80:
            suggestions.append({
                'type': 'security',
                'priority': 'medium',
                'title': 'Security Score Below Threshold',
                'description': f"Security score is {security_score}/100. Consider implementing security best practices.",
                'confidence': 0.8
            })
        
        # Add specific security recommendations
        vulnerabilities = security_scan.get('vulnerabilities', [])
        vuln_types = set(v.get('category') for v in vulnerabilities)
        
        if 'sql_injection' in vuln_types:
            suggestions.append({
                'type': 'security',
                'priority': 'high',
                'title': 'SQL Injection Prevention',
                'description': "Use parameterized queries or ORM to prevent SQL injection attacks.",
                'confidence': 0.9
            })
        
        if 'hardcoded_secrets' in vuln_types:
            suggestions.append({
                'type': 'security',
                'priority': 'medium',
                'title': 'Credential Management',
                'description': "Move hardcoded secrets to environment variables or secure credential storage.",
                'confidence': 0.85
            })
        
        return suggestions
    
    async def _generate_style_suggestions(self, pr_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate style and best practice suggestions"""
        suggestions = []
        
        # Check PR description
        description = pr_data.get('description', '').strip()
        if len(description) < 20:
            suggestions.append({
                'type': 'documentation',
                'priority': 'low',
                'title': 'Improve PR Description',
                'description': "Consider adding a more detailed description explaining the changes and their purpose.",
                'confidence': 0.8
            })
        
        # Check PR size
        changes = pr_data.get('additions', 0) + pr_data.get('deletions', 0)
        if changes > 500:
            suggestions.append({
                'type': 'process',
                'priority': 'medium',
                'title': 'Large PR Size',
                'description': "This PR has many changes. Consider splitting into smaller, focused PRs for easier review.",
                'confidence': 0.7
            })
        
        # Check commit count
        commits = pr_data.get('commits', 1)
        if commits > 20:
            suggestions.append({
                'type': 'process',
                'priority': 'low',
                'title': 'Many Commits',
                'description': "Consider squashing related commits for a cleaner history.",
                'confidence': 0.6
            })
        
        return suggestions
    
    async def _generate_overall_assessment(self, review_result: Dict[str, Any],
                                         pr_data: Dict[str, Any], 
                                         code_analysis: Dict[str, Any],
                                         security_scan: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall assessment and recommendation"""
        
        # Calculate confidence score based on various factors
        confidence_factors = []
        
        # Code quality factor
        code_score = code_analysis.get('overall_score', 100)
        confidence_factors.append(min(1.0, code_score / 100))
        
        # Security factor
        security_score = security_scan.get('security_score', 100)
        confidence_factors.append(min(1.0, security_score / 100))
        
        # Calculate overall confidence
        review_result['confidence_score'] = sum(confidence_factors) / len(confidence_factors)
        
        # Determine recommendation
        critical_issues = sum(1 for s in review_result['suggestions'] if s['priority'] == 'critical')
        high_issues = sum(1 for s in review_result['suggestions'] if s['priority'] == 'high')
        
        if critical_issues > 0:
            review_result['overall_recommendation'] = 'REQUEST_CHANGES'
            review_result['summary'] = "Critical issues found that must be addressed before merging."
        elif high_issues > 2:
            review_result['overall_recommendation'] = 'REQUEST_CHANGES'
            review_result['summary'] = "Multiple high-priority issues need to be resolved."
        elif code_score > 85 and security_score > 85:
            review_result['overall_recommendation'] = 'APPROVE'
            review_result['summary'] = "Code looks good! Minor suggestions for improvement."
        else:
            review_result['overall_recommendation'] = 'COMMENT'
            review_result['summary'] = "Good work with some areas for improvement."
        
        # Generate praise points
        review_result['praise_points'] = self._generate_praise_points(pr_data, code_analysis)
        
        # Generate improvement areas
        review_result['improvement_areas'] = self._generate_improvement_areas(review_result['suggestions'])
        
        return review_result
    
    def _generate_praise_points(self, pr_data: Dict[str, Any], code_analysis: Dict[str, Any]) -> List[str]:
        """Generate positive feedback points"""
        praise = []
        
        code_score = code_analysis.get('overall_score', 0)
        if code_score > 90:
            praise.append("🎉 Excellent code quality! Well structured and maintainable.")
        elif code_score > 80:
            praise.append("👍 Good code quality with room for minor improvements.")
        
        # Check for good practices
        description = pr_data.get('description', '')
        if len(description) > 100:
            praise.append("📝 Great job providing a detailed PR description!")
        
        changes = pr_data.get('additions', 0) + pr_data.get('deletions', 0)
        if changes < 100:
            praise.append("✨ Nice focused changes! Easy to review and understand.")
        
        files_changed = pr_data.get('changed_files', 0)
        if files_changed <= 3:
            praise.append("🎯 Well-scoped PR affecting minimal files.")
        
        return praise
    
    def _generate_improvement_areas(self, suggestions: List[Dict[str, Any]]) -> List[str]:
        """Generate improvement area summaries"""
        areas = []
        
        # Group suggestions by type
        suggestion_types = {}
        for suggestion in suggestions:
            stype = suggestion['type']
            if stype not in suggestion_types:
                suggestion_types[stype] = 0
            suggestion_types[stype] += 1
        
        # Generate improvement areas
        if suggestion_types.get('security', 0) > 0:
            areas.append("🔒 Security: Address vulnerability findings")
        
        if suggestion_types.get('improvement', 0) > 0:
            areas.append("📈 Code Quality: Improve overall code quality metrics")
        
        if suggestion_types.get('refactoring', 0) > 0:
            areas.append("🔧 Refactoring: Reduce complexity and improve structure")
        
        if suggestion_types.get('documentation', 0) > 0:
            areas.append("📚 Documentation: Enhance code and PR documentation")
        
        return areas
    
    async def _generate_inline_comments(self, pr_data: Dict[str, Any], 
                                      code_analysis: Dict[str, Any],
                                      security_scan: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate specific inline comments for files and lines"""
        inline_comments = []
        
        # Add comments for code analysis issues
        for file_analysis in code_analysis.get('file_analyses', []):
            filename = file_analysis['filename']
            
            for issue in file_analysis.get('issues', []):
                if issue['severity'] in ['error', 'warning']:
                    inline_comments.append({
                        'path': filename,
                        'line': issue['line'],
                        'body': f"**{issue['type'].title()} Issue**: {issue['message']}\n\n💡 **Suggestion**: {issue['suggestion']}",
                        'severity': issue['severity']
                    })
        
        # Add comments for security vulnerabilities
        for vuln in security_scan.get('vulnerabilities', []):
            if vuln['severity'] in ['error', 'warning']:
                inline_comments.append({
                    'path': vuln['filename'],
                    'line': vuln['line'], 
                    'body': f"🔒 **Security**: {vuln['message']}\n\n🛡️ **Fix**: {vuln['suggestion']}\n\n📋 **CWE**: {vuln.get('cwe_id', 'N/A')}",
                    'severity': vuln['severity']
                })
        
        # Limit inline comments to avoid spam
        return inline_comments[:15]  # Max 15 inline comments
    
    def _calculate_review_confidence(self, analysis_results: List[Dict[str, Any]]) -> float:
        """Calculate confidence score for the review"""
        # Base confidence
        confidence = 0.8
        
        # Adjust based on analysis completeness
        if len(analysis_results) > 0:
            confidence += 0.1
        
        # Adjust based on issue severity distribution
        critical_count = sum(1 for result in analysis_results 
                           if result.get('severity') == 'error')
        if critical_count > 0:
            confidence += 0.1  # More confident about critical issues
        
        return min(1.0, confidence)
    
    async def generate_review_summary(self, review_data: Dict[str, Any]) -> str:
        """Generate a comprehensive review summary"""
        
        summary_parts = []
        
        # Header with overall recommendation
        recommendation = review_data['overall_recommendation']
        confidence = review_data['confidence_score']
        
        if recommendation == 'APPROVE':
            summary_parts.append("## ✅ **APPROVED** - Great work!")
        elif recommendation == 'REQUEST_CHANGES':
            summary_parts.append("## ❌ **CHANGES REQUESTED** - Please address the following issues")
        else:
            summary_parts.append("## 💬 **COMMENTS** - Good work with suggestions for improvement")
        
        summary_parts.append(f"*Confidence Score: {confidence:.1%}*")
        summary_parts.append("")
        
        # Add main summary
        summary_parts.append(f"### Summary")
        summary_parts.append(review_data['summary'])
        summary_parts.append("")
        
        # Add praise points if any
        if review_data['praise_points']:
            summary_parts.append("### 🎉 What's Working Well")
            for praise in review_data['praise_points']:
                summary_parts.append(f"- {praise}")
            summary_parts.append("")
        
        # Add improvement areas if any
        if review_data['improvement_areas']:
            summary_parts.append("### 📋 Areas for Improvement")
            for area in review_data['improvement_areas']:
                summary_parts.append(f"- {area}")
            summary_parts.append("")
        
        # Add key suggestions
        high_priority_suggestions = [s for s in review_data['suggestions'] 
                                   if s['priority'] in ['critical', 'high']]
        
        if high_priority_suggestions:
            summary_parts.append("### 🔥 Priority Issues")
            for suggestion in high_priority_suggestions[:5]:  # Limit to top 5
                priority_emoji = "🚨" if suggestion['priority'] == 'critical' else "⚠️"
                summary_parts.append(f"- {priority_emoji} **{suggestion['title']}**: {suggestion['description']}")
            summary_parts.append("")
        
        # Add footer
        summary_parts.append("---")
        summary_parts.append("*Generated by CodeGuardian AI - Intelligent PR Review Agent*")
        
        return "\n".join(summary_parts)