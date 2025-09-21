"""
Pydantic schemas for API request/response models
"""

from pydantic import BaseModel
from typing import Dict, List, Any, Optional
from datetime import datetime

class HealthCheckResponse(BaseModel):
    status: str
    services: Dict[str, bool]
    timestamp: str

class PRInfo(BaseModel):
    id: int
    number: int
    title: str
    description: str
    author: str
    state: str
    created_at: str
    updated_at: str
    base_branch: str
    head_branch: str
    base_sha: str
    head_sha: str
    mergeable: Optional[bool]
    additions: int
    deletions: int
    changed_files: int
    commits: int
    url: str

class CodeMetrics(BaseModel):
    complexity: float
    maintainability: float
    test_coverage: float
    code_duplication: float

class CodeAnalysis(BaseModel):
    overall_score: float
    total_files: int
    analyzed_files: int
    issues: List[Dict[str, Any]]
    metrics: CodeMetrics
    file_analyses: List[Dict[str, Any]]

class SecuritySummary(BaseModel):
    critical: int
    high: int
    medium: int
    low: int

class SecurityScan(BaseModel):
    total_files: int
    scanned_files: int
    vulnerabilities: List[Dict[str, Any]]
    security_score: int
    summary: SecuritySummary
    recommendations: List[str]

class AIReview(BaseModel):
    overall_recommendation: str
    confidence_score: float
    summary: str
    suggestions: List[Dict[str, Any]]
    inline_comments: List[Dict[str, Any]]
    praise_points: List[str]
    improvement_areas: List[str]

class AnalysisMetadata(BaseModel):
    platform: str
    repository: str
    pr_number: int
    analyzed_at: str
    analysis_duration: float
    analyzer_version: str

class KeyMetrics(BaseModel):
    code_quality_score: float
    security_score: int
    total_issues: int
    files_analyzed: int
    lines_changed: int

class AnalysisSummary(BaseModel):
    overall_health_score: int
    recommendation: str
    confidence: float
    key_metrics: KeyMetrics
    risk_factors: List[str]
    positive_aspects: List[str]
    action_items: List[str]

class PRAnalysisResponse(BaseModel):
    metadata: AnalysisMetadata
    pr_info: PRInfo
    code_analysis: CodeAnalysis
    security_scan: SecurityScan
    ai_review: AIReview
    summary: AnalysisSummary
    comment_posted: Optional[bool] = None

class RepositoryInfoResponse(BaseModel):
    name: str
    full_name: str
    description: Optional[str]
    private: bool
    language: Optional[str]
    languages: Dict[str, int]
    default_branch: str
    stars: int
    forks: int
    created_at: str
    updated_at: str
    url: str

class BulkSummary(BaseModel):
    avg_code_quality: float
    avg_security_score: float
    total_issues: int
    recommendations: List[str]

class BulkAnalysisResult(BaseModel):
    pr_number: int
    title: str
    status: str
    analysis: Optional[PRAnalysisResponse] = None
    error: Optional[str] = None

class BulkAnalysisResponse(BaseModel):
    repository: str
    platform: str
    total_prs: int
    analyzed_prs: int
    failed_prs: int
    results: List[BulkAnalysisResult]
    summary: BulkSummary

class WebhookRequest(BaseModel):
    action: Optional[str]
    object_kind: Optional[str]
    pull_request: Optional[Dict[str, Any]]
    merge_request: Optional[Dict[str, Any]]
    repository: Optional[Dict[str, Any]]
    project: Optional[Dict[str, Any]]

class PlatformInfo(BaseModel):
    name: str
    key: str
    status: str
    features: List[str]

class SupportedPlatformsResponse(BaseModel):
    platforms: List[PlatformInfo]
    total_platforms: int

class StatsResponse(BaseModel):
    total_prs_analyzed: int
    total_repositories: int
    avg_analysis_time: float
    avg_code_quality_score: float
    avg_security_score: float
    uptime: str
    version: str