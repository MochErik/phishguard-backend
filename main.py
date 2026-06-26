"""
PhishGuard Backend — FastAPI
Entry point: uvicorn main:app --host 0.0.0.0 --port 8000
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from loguru import logger
import time

from core.config import settings
from core.database import init_db
from api.routes import router

# ── Rate limiter (10 000 req / day per IP) ──────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10000/day", "500/hour", "60/minute"],
    storage_uri=settings.REDIS_URL,
)

app = FastAPI(
    title="PhishGuard API",
    description="Phishing Detection Engine — URL, Email, SMS, QR, Web, Document",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ── Middleware ───────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000, 2)
    logger.info(f"{request.method} {request.url.path} → {response.status_code} [{duration}ms]")
    return response


# ── Startup ──────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    await init_db()
    logger.info("PhishGuard API started ✓")


# ── Routes ───────────────────────────────────────────────────────────────────
app.include_router(router, prefix="/api/v1")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "PhishGuard API"}
