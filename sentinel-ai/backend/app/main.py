"""
SentinelAI — Multi-Agent Penetration Testing and Security Assessment Platform

Main FastAPI application entry point.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.db.database import init_db, SessionLocal
from app.api.routes import router
from app.models import User, UserRole
from app.security.auth import hash_password

# ── Logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("sentinel_ai")

settings = get_settings()


def _seed_default_users(db):
    """Create default users if they don't exist (for demo/dev setup)."""
    defaults = [
        {"username": "admin", "email": "admin@sentinel-ai.local", "password": "admin123", "role": UserRole.ADMIN},
        {"username": "analyst", "email": "analyst@sentinel-ai.local", "password": "analyst123", "role": UserRole.ANALYST},
        {"username": "viewer", "email": "viewer@sentinel-ai.local", "password": "viewer123", "role": UserRole.VIEWER},
    ]
    for u in defaults:
        existing = db.query(User).filter(User.username == u["username"]).first()
        if not existing:
            user = User(
                username=u["username"],
                email=u["email"],
                hashed_password=hash_password(u["password"]),
                role=u["role"],
            )
            db.add(user)
            logger.info("Created default user: %s (role: %s)", u["username"], u["role"].value)
    db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    logger.info("═" * 60)
    logger.info("  SentinelAI starting up...")
    logger.info("  Environment: %s", settings.app_env)
    logger.info("  Demo mode: %s", settings.is_demo_mode)
    logger.info("  Gemini configured: %s", settings.is_gemini_configured)
    logger.info("  Database: %s", "SQLite" if settings.database_url.startswith("sqlite") else "PostgreSQL")
    logger.info("═" * 60)

    # Initialize database
    init_db()

    # Seed default users
    db = SessionLocal()
    try:
        _seed_default_users(db)
    finally:
        db.close()

    yield

    logger.info("SentinelAI shutting down...")


# ── App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="SentinelAI",
    description="Multi-Agent Penetration Testing and Security Assessment Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(router)

# Mount frontend dashboard (if directory exists)
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))
if os.path.exists(frontend_dir):
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
    logger.info("Mounted frontend dashboard from %s", frontend_dir)


# ── Global exception handler ─────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch unhandled exceptions — never expose internals."""
    logger.error("Unhandled exception: %s", str(exc), exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred. Please try again later."},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.app_env == "development",
    )
