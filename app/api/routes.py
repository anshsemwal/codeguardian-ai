"""
API Routes for CodeGuardian AI
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from typing import Dict, Any, List, Optional
import logging

from ..services.pr_service import PRService
from .schemas import (
    PRAnalysisResponse,
    BulkAnalysisResponse,
    HealthCheckResponse,
    RepositoryInfoResponse
)

logger = logging.getLogger(__name__)

router = APIRouter()
pr_service = PRService()

@router.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Health check endpoint"""
    try:
        health_status = await pr_service.health_check()
        return health_status
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/{platform}/{repo_owner}/{repo_name}/{pr_number}", 
            response_model=PRAnalysisResponse)
async def analyze_pr(
    platform: str,
    repo_owner: str, 
    repo_name: str,
    pr_number: int,
    post_comment: bool = Query(False, description="Post review comment on PR")
):
    """Analyze a specific pull request"""
    
    try:
        # Validate platform
        if platform.lower() not in ['github', 'gitlab']:
            raise HTTPException(status_code=400, detail="Platform must be 'github' or 'gitlab'")
        
        logger.info(f"Analyzing {platform} PR #{pr_number} in {repo_owner}/{repo_name}")
        
        # Run analysis
        analysis = await pr_service.analyze_pr(platform, repo_owner, repo_name, pr_number)
        
        # Post comment if requested
        if post_comment:
            try:
                comment_posted = await pr_service.post_review_comment(
                    platform, repo_owner, repo_name, pr_number, analysis['ai_review']
                )
                analysis['comment_posted'] = comment_posted
            except Exception as e:
                logger.warning(f"Failed to post comment: {e}")
                analysis['comment_posted'] = False
        
        return analysis
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.get("/repository/{platform}/{repo_owner}/{repo_name}/info",
           response_model=RepositoryInfoResponse)
async def get_repository_info(platform: str, repo_owner: str, repo_name: str):
    """Get repository information"""
    
    try:
        if platform.lower() not in ['github', 'gitlab']:
            raise HTTPException(status_code=400, detail="Platform must be 'github' or 'gitlab'")
        
        repo_info = await pr_service.get_repository_info(platform, repo_owner, repo_name)
        return repo_info
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to get repository info: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/bulk-analyze/{platform}/{repo_owner}/{repo_name}",
            response_model=BulkAnalysisResponse)
async def bulk_analyze_repository(
    platform: str, 
    repo_owner: str, 
    repo_name: str,
    background_tasks: BackgroundTasks,
    post_comments: bool = Query(False, description="Post review comments on PRs")
):
    """Analyze all open PRs in a repository"""
    
    try:
        if platform.lower() not in ['github', 'gitlab']:
            raise HTTPException(status_code=400, detail="Platform must be 'github' or 'gitlab'")
        
        logger.info(f"Starting bulk analysis for {repo_owner}/{repo_name}")
        
        # Run bulk analysis
        bulk_results = await pr_service.bulk_analyze_prs(platform, repo_owner, repo_name)
        
        # Post comments in background if requested
        if post_comments:
            for result in bulk_results['results']:
                if result['status'] == 'success':
                    background_tasks.add_task(
                        pr_service.post_review_comment,
                        platform, repo_owner, repo_name,
                        result['pr_number'],
                        result['analysis']['ai_review']
                    )
        
        return bulk_results
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Bulk analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/repository/{platform}/{repo_owner}/{repo_name}/prs")
async def list_pull_requests(
    platform: str,
    repo_owner: str, 
    repo_name: str,
    state: str = Query("open", description="PR state: open, closed, all")
):
    """List pull requests for a repository"""
    
    try:
        if platform.lower() not in ['github', 'gitlab']:
            raise HTTPException(status_code=400, detail="Platform must be 'github' or 'gitlab'")
        
        prs = await pr_service.list_open_prs(platform, repo_owner, repo_name)
        
        return {
            "repository": f"{repo_owner}/{repo_name}",
            "platform": platform,
            "state": state,
            "total_prs": len(prs),
            "pull_requests": prs
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to list PRs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/webhook/{platform}")
async def webhook_handler(platform: str, payload: dict):
    """Handle webhooks from GitHub/GitLab"""
    
    try:
        logger.info(f"Received {platform} webhook")
        
        # Basic webhook validation would go here
        # For now, just log the event
        event_type = payload.get('action') or payload.get('object_kind')
        logger.info(f"Webhook event type: {event_type}")
        
        # Handle pull request events
        if event_type in ['opened', 'synchronize', 'merge_request']:
            # Extract PR information from payload
            if platform.lower() == 'github':
                pr_data = payload.get('pull_request', {})
                repo_data = payload.get('repository', {})
            elif platform.lower() == 'gitlab':
                pr_data = payload.get('merge_request', {})
                repo_data = payload.get('project', {})
            else:
                raise HTTPException(status_code=400, detail="Unsupported platform")
            
            if pr_data and repo_data:
                # Extract details
                pr_number = pr_data.get('number') or pr_data.get('iid')
                repo_owner = repo_data.get('owner', {}).get('login') or repo_data.get('namespace', {}).get('path')
                repo_name = repo_data.get('name') or repo_data.get('path')
                
                if pr_number and repo_owner and repo_name:
                    logger.info(f"Auto-analyzing PR #{pr_number} from webhook")
                    
                    # Trigger analysis in background
                    try:
                        analysis = await pr_service.analyze_pr(platform, repo_owner, repo_name, pr_number)
                        
                        # Post review comment automatically
                        await pr_service.post_review_comment(
                            platform, repo_owner, repo_name, pr_number, analysis['ai_review']
                        )
                        
                        return {"status": "success", "message": "PR analyzed and reviewed"}
                    
                    except Exception as e:
                        logger.error(f"Auto-analysis failed: {e}")
                        return {"status": "error", "message": str(e)}
        
        return {"status": "received", "message": "Webhook processed"}
        
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_stats():
    """Get system statistics"""
    try:
        # This would typically come from a database
        # For now, return mock stats
        return {
            "total_prs_analyzed": 0,
            "total_repositories": 0,
            "avg_analysis_time": 0.0,
            "avg_code_quality_score": 0.0,
            "avg_security_score": 0.0,
            "uptime": "0 days",
            "version": "1.0.0"
        }
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/supported-platforms")
async def get_supported_platforms():
    """Get list of supported platforms"""
    platforms = []
    
    if pr_service.github_service:
        platforms.append({
            "name": "GitHub",
            "key": "github",
            "status": "active",
            "features": ["pr_analysis", "review_comments", "webhooks"]
        })
    
    if pr_service.gitlab_service:
        platforms.append({
            "name": "GitLab",
            "key": "gitlab", 
            "status": "active",
            "features": ["pr_analysis", "review_comments", "webhooks"]
        })
    
    return {
        "platforms": platforms,
        "total_platforms": len(platforms)
    }