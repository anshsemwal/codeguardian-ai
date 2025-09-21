"""
PR Service - Main orchestrator for PR analysis and review
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime

from .github_service import GitHubService
from .gitlab_service import GitLabService
from .code_analyzer import CodeAnalyzer
from .security_scanner import SecurityScanner
from .ai_reviewer import AIReviewer
from ..config import settings

logger = logging.getLogger(__name__)

class PRService:
    def __init__(self):
        # Initialize services
        self.github_service = None
        self.gitlab_service = None
        self.code_analyzer = CodeAnalyzer()
        self.security_scanner = SecurityScanner()
        self.ai_reviewer = AIReviewer()
        
        # Initialize platform services based on configuration
        if settings.github_token:
            try:
                self.github_service = GitHubService()
                logger.info("GitHub service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize GitHub service: {e}")
                raise
        
        if settings.gitlab_token:
            try:
                self.gitlab_service = GitLabService()
                logger.info("GitLab service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize GitLab service: {e}")

    async def analyze_pr(self, platform: str, repo_owner: str, repo_name: str, pr_number: int) -> Dict[str, Any]:
        """Main method to analyze a PR across all dimensions"""
        try:
            logger.info(f"Starting analysis for {platform}/{repo_owner}/{repo_name}/pull/{pr_number}")
            
            # Get the appropriate service
            service = self._get_service(platform)
            if not service:
                raise ValueError(f"No service available for platform: {platform}")
            
            # Step 1: Fetch PR data
            pr_data = await service.get_pull_request(repo_owner, repo_name, pr_number)
            if not pr_data:
                raise ValueError("Failed to fetch PR data")
            
            # Step 2: Run analysis in parallel
            analysis_tasks = [
                self.code_analyzer.analyze_code(pr_data.get('files', [])),
                self.security_scanner.scan_files(pr_data.get('files', []))
            ]
            
            code_analysis, security_scan = await asyncio.gather(*analysis_tasks)
            
            # Step 3: Generate AI review
            ai_review = await self.ai_reviewer.review_code_changes(
                pr_data, code_analysis, security_scan
            )
            
            # Step 4: Compile results
            return {
                'metadata': {
                    'platform': platform,
                    'repository': f"{repo_owner}/{repo_name}",
                    'pr_number': pr_number,
                    'analyzed_at': datetime.utcnow().isoformat(),
                },
                'pr': pr_data,
                'analysis': {
                    'code_quality': code_analysis,
                    'security': security_scan,
                    'ai_review': ai_review
                }
            }
            
        except Exception as e:
            logger.error(f"Error in analyze_pr: {str(e)}", exc_info=True)
            raise

    def _get_service(self, platform: str):
        """Get the appropriate service for the platform"""
        platform = platform.lower()
        
        if platform == 'github':
            if not self.github_service:
                raise ValueError("GitHub service not available. Check configuration.")
            return self.github_service
        elif platform == 'gitlab':
            if not self.gitlab_service:
                raise ValueError("GitLab service not available. Check configuration.")
            return self.gitlab_service
        else:
            raise ValueError(f"Unsupported platform: {platform}")

    async def health_check(self) -> Dict[str, Any]:
        """Check health of all services"""
        health = {
            'status': 'healthy',
            'services': {
                'github': False,
                'gitlab': False,
                'code_analyzer': True,
                'security_scanner': True,
                'ai_reviewer': True
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Test GitHub connection
        if self.github_service:
            try:
                health['services']['github'] = await self.github_service.test_connection()
                if not health['services']['github']:
                    health['status'] = 'degraded'
            except Exception as e:
                logger.error(f"GitHub health check failed: {e}")
                health['services']['github'] = False
                health['status'] = 'degraded'
        
        return health