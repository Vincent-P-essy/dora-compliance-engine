"""Flask configuration, loaded from the environment (`.env` supported)."""

from __future__ import annotations

import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


class Config:
    # flask-smorest / OpenAPI — interactive docs served at /api/docs/swagger
    API_TITLE = "dora-compliance-engine API"
    API_VERSION = "v1"
    OPENAPI_VERSION = "3.0.3"
    OPENAPI_URL_PREFIX = "/api/docs"
    OPENAPI_SWAGGER_UI_PATH = "/swagger"
    OPENAPI_SWAGGER_UI_URL = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"

    # Insecure fallbacks exist for local development only; docker-compose and
    # production must provide real values through the environment.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-not-for-production")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-only-jwt-not-for-production")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        seconds=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES", 3600))
    )

    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///dora.db")
    GATE_DEFAULT_MIN_SCORE = float(os.environ.get("GATE_DEFAULT_MIN_SCORE", 75))


class TestConfig(Config):
    TESTING = True
    DATABASE_URL = "sqlite://"  # tests override with a per-test temporary file
    JWT_SECRET_KEY = "test-jwt-secret-0123456789abcdef0123456789abcdef"
