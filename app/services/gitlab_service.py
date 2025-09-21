"""
GitLab Service - Handle GitLab API interactions
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
import gitlab
import requests
import base64

from ..config import settings
from ..utils.helpers import parse_diff, extract_changed_files

logger = logging.getLogger(__name__)

class GitLabService:
    def __init__(self):
        if not settings.gitlab_token:
            raise ValueError("GitLab token not configured")
        
        self.gitlab = gitlab.Gitlab(settings.gitlab_url, private_token=settings.gitlab_token)
        self.session = requests.Session()
        self.session.headers.update({
            'PRIVATE-TOKEN': settings.gitlab_token,
            'Content-Type': 'application/json'
        })
    
    async def get_repository(self, owner: str, name: str):
        """Get project object"""
        try:
            project_path = f"{owner}/{name}"
            project = self.gitlab.projects.get(project_path)
            return project
        except gitlab.exceptions.GitlabGetError as e:
            logger.error(f"Failed to get project {owner}/{name}: {e}")
            raise
    
    async def get_pull_request(self, owner: str, name: str, pr_number: int) -> Dict[str, Any]:
        """Get merge request with detailed information"""
        try:
            project = await self.get_repository(owner, name)
            mr = project.mergerequests.get(pr_number)
            
            # Get MR details
            pr_data = {
                'id': mr.id,
                'number': mr.iid,  # GitLab uses iid for MR number
                'title': mr.title,
                'description': mr.description or "",
                'author': mr.author['username'],
                'state': mr.state,
                'created_at': mr.created_at,
                'updated_at': mr.updated_at,
                'base_branch': mr.target_branch,
                'head_branch': mr.source_branch,
                'base_sha': mr.diff_refs['base_sha'] if mr.diff_refs else '',
                'head_sha': mr.diff_refs['head_sha'] if mr.diff_refs else '',
                'mergeable': mr.merge_status == 'can_be_merged',
                'additions': getattr(mr, 'additions', 0),
                'deletions': getattr(mr, 'deletions', 0),
                'changed_files': len(mr.changes()['changes']) if hasattr(mr, 'changes') else 0,
                'commits': len(mr.commits()),
                'url': mr.web_url,
                'diff_url': f"{mr.web_url}/diffs",
                'patch_url': f"{mr.web_url}.patch"
            }
            
            return pr_data
        except gitlab.exceptions.GitlabGetError as e:
            logger.error(f"Failed to get MR {pr_number}: {e}")
            raise
    
    async def get_pr_files(self, owner: str, name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Get files changed in MR with their content and diff"""
        try:
            project = await self.get_repository(owner, name)
            mr = project.mergerequests.get(pr_number)
            
            files_data = []
            changes = mr.changes()
            
            for change in changes['changes']:
                file_data = {
                    'filename': change['new_path'] or change['old_path'],
                    'status': self._determine_file_status(change),
                    'additions': 0,  # GitLab doesn't provide line counts directly
                    'deletions': 0,
                    'changes': 0,
                    'patch': change.get('diff', ''),
                    'raw_url': None,
                    'blob_url': None,
                    'contents_url': None
                }
                
                # Count additions/deletions from diff
                if file_data['patch']:
                    lines = file_data['patch'].split('\n')
                    additions = sum(1 for line in lines if line.startswith('+') and not line.startswith('+++'))
                    deletions = sum(1 for line in lines if line.startswith('-') and not line.startswith('---'))
                    file_data['additions'] = additions
                    file_data['deletions'] = deletions
                    file_data['changes'] = additions + deletions
                
                # Get file content if it's not too large and not removed
                if (change['new_file'] or not change['deleted_file']) and file_data['changes'] < 1000:
                    try:
                        content = await self._get_file_content(
                            project, file_data['filename'], mr.diff_refs['head_sha']
                        )
                        file_data['content'] = content
                    except Exception as e:
                        logger.warning(f"Failed to get content for {file_data['filename']}: {e}")
                        file_data['content'] = None
                
                files_data.append(file_data)
            
            return files_data
        except gitlab.exceptions.GitlabGetError as e:
            logger.error(f"Failed to get MR files: {e}")
            raise
    
    def _determine_file_status(self, change: Dict[str, Any]) -> str:
        """Determine file status from GitLab change"""
        if change.get('new_file'):
            return 'added'
        elif change.get('deleted_file'):
            return 'removed'
        elif change.get('renamed_file'):
            return 'renamed'
        else:
            return 'modified'
    
    async def _get_file_content(self, project, path: str, sha: str) -> Optional[str]:
        """Get file content at specific commit"""
        try:
            file_obj = project.files.get(file_path=path, ref=sha)
            content = file_obj.decode()
            return content.decode('utf-8') if isinstance(content, bytes) else content
        except Exception as e:
            logger.error(f"Failed to get file content: {e}")
            return None
    
    async def get_pr_diff(self, owner: str, name: str, pr_number: int) -> str:
        """Get complete diff for MR"""
        try:
            project = await self.get_repository(owner, name)
            mr = project.mergerequests.get(pr_number)
            
            # Get raw diff
            changes = mr.changes()
            diff_parts = []
            
            for change in changes['changes']:
                if change.get('diff'):
                    diff_parts.append(change['diff'])
            
            return '\n'.join(diff_parts)
        except Exception as e:
            logger.error(f"Failed to get MR diff: {e}")
            raise
    
    async def post_review_comment(self, owner: str, name: str, pr_number: int, 
                                body: str, commit_sha: str, path: str, line: int) -> bool:
        """Post a review comment on specific line"""
        try:
            project = await self.get_repository(owner, name)
            mr = project.mergerequests.get(pr_number)
            
            # Create discussion on specific line
            mr.discussions.create({
                'body': body,
                'position': {
                    'position_type': 'text',
                    'new_path': path,
                    'new_line': line,
                    'base_sha': mr.diff_refs['base_sha'],
                    'start_sha': mr.diff_refs['start_sha'],
                    'head_sha': commit_sha
                }
            })
            return True
        except Exception as e:
            logger.error(f"Failed to post review comment: {e}")
            return False
    
    async def post_pr_comment(self, owner: str, name: str, pr_number: int, body: str) -> bool:
        """Post a general comment on MR"""
        try:
            project = await self.get_repository(owner, name)
            mr = project.mergerequests.get(pr_number)
            
            mr.notes.create({'body': body})
            return True
        except Exception as e:
            logger.error(f"Failed to post MR comment: {e}")
            return False
    
    async def create_review(self, owner: str, name: str, pr_number: int, 
                          event: str, body: str, comments: List[Dict] = None) -> bool:
        """Create a complete review (GitLab doesn't have review concept like GitHub)"""
        try:
            # In GitLab, we'll post the main comment and individual line comments
            success = await self.post_pr_comment(owner, name, pr_number, body)
            
            if success and comments:
                project = await self.get_repository(owner, name)
                mr = project.mergerequests.get(pr_number)
                
                for comment in comments:
                    try:
                        await self.post_review_comment(
                            owner, name, pr_number,
                            comment['body'], mr.diff_refs['head_sha'],
                            comment['path'], comment['line']
                        )
                    except Exception as e:
                        logger.warning(f"Failed to post inline comment: {e}")
            
            return success
        except Exception as e:
            logger.error(f"Failed to create review: {e}")
            return False
    
    async def get_repository_info(self, owner: str, name: str) -> Dict[str, Any]:
        """Get repository information"""
        try:
            project = await self.get_repository(owner, name)
            
            # Get languages (this might not be available in all GitLab versions)
            languages = {}
            try:
                languages_data = project.languages()
                languages = dict(languages_data)
            except Exception:
                pass
            
            return {
                'name': project.name,
                'full_name': project.path_with_namespace,
                'description': project.description,
                'private': project.visibility == 'private',
                'language': None,  # GitLab doesn't have a primary language field
                'languages': languages,
                'default_branch': project.default_branch,
                'stars': project.star_count,
                'forks': project.forks_count,
                'created_at': project.created_at,
                'updated_at': project.last_activity_at,
                'url': project.web_url
            }
        except Exception as e:
            logger.error(f"Failed to get repository info: {e}")
            raise
    
    async def list_pull_requests(self, owner: str, name: str, state: str = 'opened') -> List[Dict[str, Any]]:
        """List merge requests for a repository"""
        try:
            project = await self.get_repository(owner, name)
            
            # Map state to GitLab terminology
            gitlab_state = state
            if state == 'open':
                gitlab_state = 'opened'
            elif state == 'closed':
                gitlab_state = 'closed'
            
            mrs = project.mergerequests.list(state=gitlab_state, all=True)
            
            pr_list = []
            for mr in mrs[:50]:  # Limit to 50 MRs
                pr_list.append({
                    'number': mr.iid,
                    'title': mr.title,
                    'author': mr.author['username'],
                    'state': mr.state,
                    'created_at': mr.created_at,
                    'updated_at': mr.updated_at,
                    'url': mr.web_url
                })
            
            return pr_list
        except Exception as e:
            logger.error(f"Failed to list MRs: {e}")
            raise
    
    async def test_connection(self) -> bool:
        """Test GitLab API connection"""
        try:
            user = self.gitlab.user
            logger.info(f"Connected to GitLab as: {user.username}")
            return True
        except Exception as e:
            logger.error(f"GitLab connection failed: {e}")
            return False