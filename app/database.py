"""
Database configuration and models
"""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from .config import settings

# Create database engine
engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {}
)

# Create SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create Base class
Base = declarative_base()

# Database Models
class Repository(Base):
    __tablename__ = "repositories"
    
    id = Column(Integer, primary_key=True, index=True)
    platform = Column(String(50), nullable=False)
    owner = Column(String(100), nullable=False)
    name = Column(String(100), nullable=False)
    full_name = Column(String(200), nullable=False)
    url = Column(String(500))
    webhook_url = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class PullRequest(Base):
    __tablename__ = "pull_requests"
    
    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, nullable=False)
    platform = Column(String(50), nullable=False)
    pr_number = Column(Integer, nullable=False)
    title = Column(String(500))
    description = Column(Text)
    author = Column(String(100))
    state = Column(String(50))
    base_branch = Column(String(100))
    head_branch = Column(String(100))
    base_sha = Column(String(100))
    head_sha = Column(String(100))
    additions = Column(Integer, default=0)
    deletions = Column(Integer, default=0)
    changed_files = Column(Integer, default=0)
    commits = Column(Integer, default=0)
    url = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Analysis(Base):
    __tablename__ = "analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    pull_request_id = Column(Integer, nullable=False)
    overall_score = Column(Float)
    code_quality_score = Column(Float)
    security_score = Column(Float)
    complexity_score = Column(Float)
    total_issues = Column(Integer, default=0)
    critical_issues = Column(Integer, default=0)
    high_issues = Column(Integer, default=0)
    medium_issues = Column(Integer, default=0)
    low_issues = Column(Integer, default=0)
    ai_recommendation = Column(String(50))
    ai_confidence = Column(Float)
    analysis_duration = Column(Float)
    analyzer_version = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)

class Issue(Base):
    __tablename__ = "issues"
    
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, nullable=False)
    issue_type = Column(String(100))
    category = Column(String(100))
    severity = Column(String(50))
    message = Column(Text)
    filename = Column(String(500))
    line_number = Column(Integer)
    code_snippet = Column(Text)
    suggestion = Column(Text)
    cwe_id = Column(String(20))
    created_at = Column(DateTime, default=datetime.utcnow)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()