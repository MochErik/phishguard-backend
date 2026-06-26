from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List, Dict, Any
from enum import Enum


class ScanType(str, Enum):
    url = "url"
    email = "email"
    sms = "sms"
    qr = "qr"
    web = "web"
    document = "document"


class Verdict(str, Enum):
    safe = "safe"
    suspicious = "suspicious"
    phishing = "phishing"


# ── Requests ─────────────────────────────────────────────────────────────────

class URLScanRequest(BaseModel):
    url: str = Field(..., description="URL yang akan diperiksa", example="https://example.com")


class TextScanRequest(BaseModel):
    text: str = Field(..., max_length=10000, description="Isi email/SMS yang akan diperiksa")
    scan_type: ScanType = ScanType.email


class WebScanRequest(BaseModel):
    url: str = Field(..., description="URL halaman web yang akan discan visual")


# ── Analysis sub-results ──────────────────────────────────────────────────────

class BlacklistResult(BaseModel):
    hit: bool
    sources: List[str] = []
    threat_type: Optional[str] = None


class URLFeatures(BaseModel):
    domain: str
    tld: str
    subdomain: Optional[str]
    path_length: int
    has_ip: bool
    has_at_sign: bool
    has_double_slash: bool
    has_dash_in_domain: bool
    https: bool
    domain_age_days: Optional[int]
    suspicious_keywords: List[str]
    redirect_count: int
    url_entropy: float


class NLPResult(BaseModel):
    urgency_score: float     # 0-1: kata-kata mendesak
    threat_score: float      # 0-1: ancaman eksplisit
    reward_score: float      # 0-1: iming-iming hadiah
    link_count: int
    suspicious_phrases: List[str]
    sentiment: str           # negative/neutral/positive
    language: str


class AIAnalysis(BaseModel):
    model_name: str
    raw_score: float
    confidence: float
    top_features: List[Dict[str, Any]]
    explanation: str


# ── Final result ──────────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    scan_id: str
    scan_type: ScanType
    verdict: Verdict
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Skor risiko 0-100")
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str
    recommendations: List[str]

    blacklist: Optional[BlacklistResult] = None
    url_features: Optional[URLFeatures] = None
    nlp_result: Optional[NLPResult] = None
    ai_analysis: Optional[AIAnalysis] = None

    processing_time_ms: float
    scanned_at: str
