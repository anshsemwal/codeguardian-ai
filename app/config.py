"""
Simple Configuration for CodeGuardian AI
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Settings:
    def __init__(self):
        # App Configuration
        self.app_name = "CodeGuardian AI"
        self.debug = True
        
        # Database
        self.database_url = "sqlite:///./codeguardian.db"
        
        # GitHub Integration
        self.github_token = os.getenv('GITHUB_TOKEN')
        
        # GitLab Integration  
        self.gitlab_token = os.getenv('GITLAB_TOKEN')
        self.gitlab_url = "https://gitlab.com"
        
        # AI Configuration
        self.use_local_ai = True
        
        # Security
        self.secret_key = "codeguardian-super-secret-key"
        
        # Analysis Configuration
        self.max_file_size = 1048576  # 1MB

def get_settings():
    return Settings()

settings = get_settings()

# Simple validation
def validate_settings():
    print(f"DEBUG: GitHub token loaded: {settings.github_token[:10]}..." if settings.github_token else "No GitHub token found")
    if not settings.github_token and not settings.gitlab_token:
        raise ValueError("At least one platform token (GitHub or GitLab) must be provided")
    return True

# Initialize validation
validate_settings()