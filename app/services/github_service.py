"""
GitHub Service - Handle GitHub API interactions
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from github import Github, GithubException
from github.Repository import Repository
from github.PullRequest import PullRequest
import requests

from ..config import settings
from ..utils.helpers import parse_diff, extract_changed_files

logger = logging.getLogger(__name__)

class GitHubService:
    def __init__(self):
        if not settings.github_token:
            raise ValueError("GitHub token not configured")
        
        self.github = Github(settings.github_token, per_page=100)
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {settings.github_token}',
            'Accept': 'application/vnd.github.v3+json'
        })
        
        # Test connection on init
        try:
            user = self.github.get_user()
            logger.info(f"Connected to GitHub as: {user.login}")
        except Exception as e:
            logger.error(f"Failed to connect to GitHub: {e}")
            raise
    
    async def get_repository(self, owner: str, name: str) -> Repository:
        """Get repository object"""
        try:
            repo = self.github.get_repo(f"{owner}/{name}")
            logger.debug(f"Successfully fetched repository: {owner}/{name}")
            return repo
        except GithubException as e:
            error_msg = f"Failed to get repository {owner}/{name}: {e}"
            if hasattr(e, 'data') and 'message' in e.data:
                error_msg = f"{error_msg} - {e.data['message']}"
            logger.error(error_msg)
            raise ValueError(error_msg)
    
    async def get_pr_files(self, owner: str, repo_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Get list of files changed in a pull request"""
        try:
            logger.debug(f"Fetching files for PR {owner}/{repo_name}#{pr_number}")
            repo = await self.get_repository(owner, repo_name)
            pr = repo.get_pull(pr_number)
            
            files = []
            for file in pr.get_files():
                files.append({
                    'filename': file.filename,
                    'status': file.status,
                    'additions': file.additions,
                    'deletions': file.deletions,
                    'changes': file.changes,
                    'patch': getattr(file, 'patch', None)
                })
            logger.debug(f"Found {len(files)} files in PR {pr_number}")
            return files
            
        except Exception as e:
            error_msg = f"Failed to get files for PR {pr_number}: {str(e)}"
            logger.error(error_msg)
            return []
    
    async def get_pull_request(self, owner: str, name: str, pr_number: int) -> Dict[str, Any]:
        """Get pull request with detailed information"""
        try:
            logger.info(f"Fetching PR {owner}/{name}#{pr_number}")
            repo = await self.get_repository(owner, name)
            pr = repo.get_pull(pr_number)
            
            if not pr:
                raise ValueError(f"PR #{pr_number} not found in {owner}/{name}")

            # Get PR details
            pr_data = {
                'id': pr.id,
                'number': pr.number,
                'title': pr.title or "No title",
                'description': pr.body or "",
                'author': pr.user.login if pr.user else "Unknown",
                'state': pr.state or "unknown",
                'created_at': pr.created_at.isoformat() if pr.created_at else "",
                'updated_at': pr.updated_at.isoformat() if pr.updated_at else "",
                'base_branch': pr.base.ref if pr and pr.base else "unknown",
                'head_branch': pr.head.ref if pr and pr.head else "unknown",
                'base_sha': pr.base.sha if pr and pr.base else "",
                'head_sha': pr.head.sha if pr and pr.head else "",
                'mergeable': pr.mergeable,
                'additions': pr.additions or 0,
                'deletions': pr.deletions or 0,
                'changed_files': pr.changed_files or 0,
                'commits': pr.commits,
                'url': pr.html_url,
                'diff_url': pr.diff_url,
                'patch_url': pr.patch_url,
                'files': await self.get_pr_files(owner, name, pr_number)
            }
            
            logger.info(f"Successfully fetched PR data: {pr_data.get('title')}")
            return pr_data
            
        except GithubException as e:
            error_msg = f"GitHub API error: {e}"
            if hasattr(e, 'data') and 'message' in e.data:
                error_msg = f"GitHub API error: {e.data['message']}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
    
    async def test_connection(self) -> bool:
        """Test GitHub connection"""
        try:
            user = self.github.get_user()
            return bool(user)
        except Exception as e:
            logger.error(f"GitHub connection test failed: {e}")
            return False