"""
PhishGuard AI - API v1 Router
"""

from fastapi import APIRouter
from backend.app.api.v1.endpoints import auth, scans, dashboard, admin, health, metrics

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(scans.router)
api_router.include_router(dashboard.router)
api_router.include_router(admin.router)
api_router.include_router(metrics.router)
