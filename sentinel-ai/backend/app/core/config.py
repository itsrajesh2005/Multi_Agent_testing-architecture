"""SentinelAI — Core application settings loaded from environment variables."""

from __future__ import annotations

import os
import pathlib
from functools import lru_cache
from typing import List, Optional

from pydantic_settings import BaseSettings
from pydantic import Field, AliasChoices, field_validator

# Determine candidate .env locations across backend, project root, and workspace root
_current_file = pathlib.Path(__file__).resolve()
_backend_dir = _current_file.parent.parent.parent
_project_dir = _backend_dir.parent
_workspace_dir = _project_dir.parent

_env_candidates = [
    str(_backend_dir / ".env"),
    str(_project_dir / ".env"),
    str(_workspace_dir / ".env"),
    ".env",
]
_env_files = tuple(p for p in _env_candidates if os.path.exists(p)) or ".env"


class Settings(BaseSettings):
    """Application configuration — all secrets come from the environment."""

    # Application
    app_env: str = Field(default="development")
    app_debug: bool = Field(default=False)
    app_secret_key: str = Field(default="CHANGE-ME-generate-a-real-secret")
    app_host: str = Field(default="0.0.0.0")
    app_port: int = Field(default=8000)

    # Database
    database_url: str = Field(default="sqlite:///./sentinel_ai.db")

    # JWT
    jwt_secret_key: str = Field(default="CHANGE-ME-generate-a-jwt-secret")
    jwt_algorithm: str = Field(default="HS256")
    jwt_access_token_expire_minutes: int = Field(default=60)

    # Gemini
    gemini_api_key: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("gemini_api_key", "google_api_key", "gemini_key", "api_key"),
    )
    gemini_model: str = Field(
        default="gemini-3.8-flash",
        validation_alias=AliasChoices("gemini_model", "model"),
    )

    # Security
    allowed_lab_targets: str = Field(default="192.168.1.0/24,10.0.0.0/8,lab.local")
    demo_mode: bool = Field(default=True)
    require_human_approval: bool = Field(default=True)

    # Rate limiting
    rate_limit_requests_per_minute: int = Field(default=60)

    # CORS
    cors_origins: str = Field(default="http://localhost:5173,http://localhost:3000")

    @field_validator("gemini_api_key", mode="before")
    @classmethod
    def clean_api_key(cls, v: Optional[str]) -> Optional[str]:
        if isinstance(v, str):
            cleaned = v.strip().strip('"').strip("'")
            return cleaned or None
        return v

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def allowed_targets_list(self) -> List[str]:
        return [t.strip() for t in self.allowed_lab_targets.split(",") if t.strip()]

    @property
    def is_gemini_configured(self) -> bool:
        if not self.gemini_api_key:
            return False
        clean = self.gemini_api_key.strip().strip('"').strip("'")
        return bool(clean and clean not in ("your-gemini-api-key-here", "CHANGE-ME", ""))

    @property
    def is_demo_mode(self) -> bool:
        return self.demo_mode or not self.is_gemini_configured

    class Config:
        env_file = _env_files
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()


settings = get_settings()

