#!/usr/bin/env python3
"""
CodeGuardian AI - Application Entry Point
Run this file to start the application in development mode
"""

import os
import sys
import uvicorn
import logging

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.config import settings

def main():
    """Main entry point for the application"""
    
    # Configure logging
    log_level = "debug" if settings.debug else "info"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Print startup information
    print("🛡️  CodeGuardian AI - Intelligent PR Review Agent")
    print("=" * 50)
    print(f"Debug Mode: {settings.debug}")
    print(f"Database: {settings.database_url}")
    print(f"GitHub Integration: {'✅' if settings.github_token else '❌'}")
    print(f"GitLab Integration: {'✅' if settings.gitlab_token else '❌'}")
    print("=" * 50)
    print("Starting server...")
    print("Dashboard: http://localhost:8000")
    print("API Docs: http://localhost:8000/api/docs")
    print("Health Check: http://localhost:8000/api/health")
    print("=" * 50)
    
    # Run the application
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level=log_level,
        access_log=True
    )

if __name__ == "__main__":
    main()