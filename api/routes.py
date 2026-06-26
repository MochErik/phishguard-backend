"""
API Routes — semua endpoint deteksi phishing
"""
import time
import uuid
import hashlib
from datetime import datetime, timezone
from fastapi import APIRouter, Request, UploadFile, File, Form, Depends, HTTPException
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from loguru import logger

from models.schemas import (
    URLScanRequest, TextScanRequest, WebScanRequest,
    ScanResponse, ScanType, AIAnalysis,
)
from services.url_analyzer import extract_features, check_blacklists, heuristic_score
from services.nlp_service import analyze_text, nlp_model_score
from services.document_service import analyze_document
from services.qr_service import decode_qr, is_url
from services.aggregator import aggregate
from core.config import settings

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ── Shared builder ────────────────────────────────────────────────────────────

async def _build_url_response(url: str, scan_type: ScanType, ip: str) -> ScanResponse:
    t0 = time.perf_counter()
    scan_id = str(uuid.uuid4())

    features = extract_features(url)
    blacklist, h_score = await check_blacklists(url), heuristic_score(features)
    nlp_res = None  # URL scan tidak pakai NLP

    ai_prob, ai_conf = nlp_model_score(url)   # model bisa juga terima URL string
    ai_analysis = AIAnalysis(
        model_name="distilbert-phishing",
        raw_score=round(ai_prob, 4),
        confidence=round(ai_conf, 4),
        top_features=[
            {"feature": "has_ip", "value": features.has_ip},
            {"feature": "url_entropy", "value": features.url_entropy},
            {"feature": "suspicious_keywords", "value": len(features.suspicious_keywords)},
        ],
        explanation=(
            "Model mendeteksi pola URL mencurigakan"
            if ai_prob > 0.5 else
            "URL tidak memiliki pola phishing yang signifikan"
        ),
    )

    agg = aggregate(
        scan_type=scan_type,
        blacklist=blacklist,
        url_heuristic_score=h_score,
        ai_score=ai_prob,
    )

    return ScanResponse(
        scan_id=scan_id,
        scan_type=scan_type,
        verdict=agg["verdict"],
        risk_score=agg["risk_score"],
        confidence=agg["confidence"],
        summary=agg["summary"],
        recommendations=agg["recommendations"],
        blacklist=blacklist,
        url_features=features,
        ai_analysis=ai_analysis,
        processing_time_ms=round((time.perf_counter() - t0) * 1000, 1),
        scanned_at=_now(),
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/scan/url", response_model=ScanResponse, tags=["Scan"])
@limiter.limit("200/hour")
async def scan_url(request: Request, body: URLScanRequest):
    """
    Scan URL/Link untuk phishing.
    Gratis: 10.000 req/hari via Google Safe Browsing + PhishTank.
    """
    logger.info(f"URL scan: {body.url[:80]}")
    return await _build_url_response(body.url, ScanType.url, request.client.host)


@router.post("/scan/text", response_model=ScanResponse, tags=["Scan"])
@limiter.limit("200/hour")
async def scan_text(request: Request, body: TextScanRequest):
    """
    Scan teks Email atau SMS/WA untuk phishing.
    Menggunakan NLP model + rule-based analysis.
    """
    t0 = time.perf_counter()
    scan_id = str(uuid.uuid4())

    nlp_res = analyze_text(body.text)
    ai_prob, ai_conf = nlp_model_score(body.text)

    ai_analysis = AIAnalysis(
        model_name="bert-finetuned-phishing",
        raw_score=round(ai_prob, 4),
        confidence=round(ai_conf, 4),
        top_features=[
            {"feature": "urgency_score", "value": nlp_res.urgency_score},
            {"feature": "threat_score",  "value": nlp_res.threat_score},
            {"feature": "reward_score",  "value": nlp_res.reward_score},
            {"feature": "link_count",    "value": nlp_res.link_count},
        ],
        explanation=(
            f"Teks mengandung {len(nlp_res.suspicious_phrases)} frasa mencurigakan"
            if nlp_res.suspicious_phrases else
            "Tidak ada pola phishing signifikan terdeteksi"
        ),
    )

    agg = aggregate(
        scan_type=body.scan_type,
        nlp_result=nlp_res,
        ai_score=ai_prob,
    )

    return ScanResponse(
        scan_id=scan_id,
        scan_type=body.scan_type,
        verdict=agg["verdict"],
        risk_score=agg["risk_score"],
        confidence=agg["confidence"],
        summary=agg["summary"],
        recommendations=agg["recommendations"],
        nlp_result=nlp_res,
        ai_analysis=ai_analysis,
        processing_time_ms=round((time.perf_counter() - t0) * 1000, 1),
        scanned_at=_now(),
    )


@router.post("/scan/qr", response_model=ScanResponse, tags=["Scan"])
@limiter.limit("100/hour")
async def scan_qr(request: Request, file: UploadFile = File(...)):
    """
    Upload gambar QR Code, decode, lalu analisis URL-nya.
    """
    if file.size and file.size > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, "File terlalu besar")

    image_bytes = await file.read()
    decoded = decode_qr(image_bytes)

    if not decoded:
        raise HTTPException(422, "QR Code tidak dapat dibaca atau tidak valid")

    if is_url(decoded):
        return await _build_url_response(decoded, ScanType.qr, request.client.host)

    # QR berisi teks biasa → analisis sebagai teks
    t0 = time.perf_counter()
    scan_id = str(uuid.uuid4())
    nlp_res = analyze_text(decoded)
    ai_prob, ai_conf = nlp_model_score(decoded)
    agg = aggregate(scan_type=ScanType.qr, nlp_result=nlp_res, ai_score=ai_prob)

    return ScanResponse(
        scan_id=scan_id,
        scan_type=ScanType.qr,
        verdict=agg["verdict"],
        risk_score=agg["risk_score"],
        confidence=agg["confidence"],
        summary=agg["summary"],
        recommendations=agg["recommendations"],
        nlp_result=nlp_res,
        processing_time_ms=round((time.perf_counter() - t0) * 1000, 1),
        scanned_at=_now(),
    )


@router.post("/scan/document", response_model=ScanResponse, tags=["Scan"])
@limiter.limit("50/hour")
async def scan_document(request: Request, file: UploadFile = File(...)):
    """
    Upload dokumen (PDF, DOCX, TXT, EML).
    Ekstrak teks + URL, analisis dengan NLP + URL checker.
    """
    allowed = {".pdf", ".doc", ".docx", ".txt", ".eml", ".msg"}
    ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in allowed:
        raise HTTPException(415, f"Format tidak didukung. Gunakan: {', '.join(allowed)}")

    if file.size and file.size > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, "File terlalu besar (maks 10 MB)")

    t0 = time.perf_counter()
    scan_id = str(uuid.uuid4())
    file_bytes = await file.read()

    doc = analyze_document(file.filename, file_bytes)
    nlp_res = analyze_text(doc["extracted_text"]) if doc["extracted_text"] else None

    # Cek URL pertama yang ditemukan di dokumen
    blacklist = None
    url_features = None
    url_h_score = None
    if doc["urls_found"]:
        first_url = doc["urls_found"][0]
        url_features = extract_features(first_url)
        blacklist = await check_blacklists(first_url)
        url_h_score = heuristic_score(url_features)

    ai_prob, ai_conf = nlp_model_score(doc["extracted_text"][:512]) if doc["extracted_text"] else (0.0, 0.0)

    agg = aggregate(
        scan_type=ScanType.document,
        blacklist=blacklist,
        url_heuristic_score=url_h_score,
        nlp_result=nlp_res,
        ai_score=ai_prob,
    )

    return ScanResponse(
        scan_id=scan_id,
        scan_type=ScanType.document,
        verdict=agg["verdict"],
        risk_score=agg["risk_score"],
        confidence=agg["confidence"],
        summary=agg["summary"],
        recommendations=agg["recommendations"],
        blacklist=blacklist,
        url_features=url_features,
        nlp_result=nlp_res,
        processing_time_ms=round((time.perf_counter() - t0) * 1000, 1),
        scanned_at=_now(),
    )


@router.post("/scan/web", response_model=ScanResponse, tags=["Scan"])
@limiter.limit("30/hour")
async def scan_web(request: Request, body: WebScanRequest):
    """
    Scan visual halaman web — ambil screenshot + analisis URL.
    Lebih berat, limit lebih ketat (30/jam).
    """
    # Untuk Railway free tier, web scan hanya analisis URL-nya
    # Screenshot dengan Playwright bisa diaktifkan jika ada resource cukup
    return await _build_url_response(body.url, ScanType.web, request.client.host)


@router.get("/stats", tags=["Info"])
async def get_stats(request: Request):
    """Info penggunaan API hari ini."""
    return {
        "daily_limit": 10000,
        "note": "10.000 request gratis/hari powered by Google Safe Browsing API",
        "sources": ["Google Safe Browsing", "PhishTank", "OpenPhish", "NLP Model", "Heuristic Engine"],
    }
