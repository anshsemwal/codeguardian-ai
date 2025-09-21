"""
Main FastAPI application for CodeGuardian AI
"""

import asyncio
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import logging
from datetime import datetime
import markdown
from contextlib import asynccontextmanager
from pathlib import Path

from .config import settings
from .services.pr_service import PRService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize services
pr_service = PRService()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting CodeGuardian AI...")
    logger.info("Service health check...")
    
    # Run health check in background
    async def check_services():
        try:
            health = await pr_service.health_check()
            logger.info(f"Service health: {health}")
            if not health['services']['github']:
                logger.warning("GitHub service is not available. Check your configuration.")
        except Exception as e:
            logger.error(f"Service health check failed: {e}")

    asyncio.create_task(check_services())
    
    try:
        yield
    finally:
        # Shutdown
        logger.info("Shutting down CodeGuardian AI...")

# Create FastAPI app
app = FastAPI(
    title="CodeGuardian AI",
    description="Intelligent PR Review Agent with Multi-Platform Security & Quality Analysis",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Get the directory of the current file
current_dir = Path(__file__).parent

# Mount static files
static_dir = current_dir.parent / "static"
if not static_dir.exists():
    static_dir.mkdir(parents=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Templates
templates = Jinja2Templates(directory=str(current_dir / "templates"))

# Add custom filters
def format_datetime(value, format="%b %d, %Y %I:%M %p"):
    """Format a datetime object to a string"""
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return value
    return value.strftime(format)

def markdown_to_html(value):
    """Convert markdown to HTML"""
    if not value:
        return ""
    return markdown.markdown(value, extensions=['fenced_code', 'codehilite'])

# Register filters
templates.env.filters["datetime"] = format_datetime
templates.env.filters["markdown"] = markdown_to_html

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse(
        "dashboard.html", 
        {"request": request, "title": "CodeGuardian AI Dashboard"}
    )

@app.get("/pr/{platform}/{repo_owner}/{repo_name}/{pr_number}", response_class=HTMLResponse)
async def pr_detail(
    request: Request, 
    platform: str, 
    repo_owner: str, 
    repo_name: str, 
    pr_number: int
):
    """PR Detail Page with Analysis Results"""
    try:
        logger.info(f"Processing PR: {platform}/{repo_owner}/{repo_name}/pull/{pr_number}")
        
        try:
            analysis = await asyncio.wait_for(
                pr_service.analyze_pr(platform, repo_owner, repo_name, pr_number),
                timeout=30.0
            )
        except asyncio.TimeoutError:
            logger.error("PR analysis timed out")
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Request timed out. The server took too long to process the request."
            )
        except ValueError as e:
            logger.error(f"Invalid request: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            logger.error(f"Error analyzing PR: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to analyze PR: {str(e)}"
            )
            
        return templates.TemplateResponse(
            "pr_detail.html",
            {
                "request": request,
                "pr": analysis.get('pr', {}),
                "analysis": analysis.get('analysis', {}),
                "title": f"PR #{pr_number} Analysis"
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while processing the request: {str(e)}"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        health = await pr_service.health_check()
        return {
            "status": health['status'],
            "services": health['services'],
            "version": "1.0.0",
            "timestamp": health.get('timestamp', datetime.utcnow().isoformat())
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )

@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: HTTPException):
    """Handle 404 errors"""
    return templates.TemplateResponse(
        "404.html",
        {"request": request, "message": "The requested resource was not found."},
        status_code=404
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )