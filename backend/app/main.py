"""
PhishGuard AI - Main FastAPI Application
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.core.database import engine, Base, SessionLocal, init_db
from backend.app.core.security import get_password_hash
from backend.app.models.user import User
from backend.app.models.scan import Scan
from backend.app.models.detection_reason import DetectionReason
from backend.app.models.audit_log import AuditLog
from backend.app.services.ml_service import ml_service
from backend.app.api.v1.router import api_router
from backend.app.api.v1.endpoints.metrics import router as metrics_router

# Setup Logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("phishguard")


def seed_initial_data():
    """Create initial seed users (User and Admin) if not existing."""
    db = SessionLocal()
    try:
        # Check Admin
        admin_email = "admin@phishguard.local"
        admin = db.query(User).filter(User.email == admin_email).first()
        if not admin:
            admin_user = User(
                name="System Administrator",
                email=admin_email,
                password_hash=get_password_hash("Admin@123456"),
                role="ADMIN",
                is_active=True
            )
            db.add(admin_user)
            logger.info("Created default Administrator account: admin@phishguard.local")

        # Check Demo User
        demo_email = "user@phishguard.local"
        demo = db.query(User).filter(User.email == demo_email).first()
        if not demo:
            standard_user = User(
                name="Demo Analyst",
                email=demo_email,
                password_hash=get_password_hash("User@123456"),
                role="USER",
                is_active=True
            )
            db.add(standard_user)
            logger.info("Created default Demo User account: user@phishguard.local")

        db.commit()
    except Exception as e:
        logger.error(f"Error seeding initial database data: {e}")
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create tables, migrate schemas, and seed data
    logger.info("Initializing database schemas...")
    init_db()
    seed_initial_data()
    
    # Try loading ML Model
    ml_service.load_model()
    yield
    # Shutdown
    logger.info("PhishGuard backend shutting down.")


app = FastAPI(
    title=settings.APP_NAME,
    description="AI-Based Phishing & Scam Detection System API - 7th Semester Minor Project",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security Exception Handler: generic error masking for unhandled 500 errors
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled server exception on {request.url.path}: {exc}", exc_info=True)
    if settings.DEBUG:
        # In debug mode, provide helpful error
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": f"Internal Server Error: {str(exc)}"}
        )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred. Please contact system support."}
    )


# Register API Router
app.include_router(api_router)
app.include_router(metrics_router, prefix="/api")


@app.get("/")
def root():
    return {
        "message": "Welcome to PhishGuard AI - Phishing & Scam Detection API",
        "docs": "/docs",
        "health": "/api/v1/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
