"""
NLP Engine — Phishing Text Classifier
Menggunakan HuggingFace Space API
"""
import re
import os
import httpx
from typing import List, Tuple
from loguru import logger
from models.schemas import NLPResult

HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY", "")
HF_SPACE_URL = os.getenv("HF_SPACE_URL", "").rstrip("/")
HF_MODEL_URL = "https://api-inference.huggingface.co/models/ealvaradob/bert-finetuned-phishing"


async def _call_hf_api(text: str) -> Tuple[float, float]:
    """Panggil HuggingFace Space API, fallback ke Inference API."""

    # Coba HF Space dulu
    if HF_SPACE_URL:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(
                    f"{HF_SPACE_URL}/run/predict",
                    json={"data": [text[:512]]},
                )
                if r.status_code == 200:
                    data = r.json()
                    result = data.get("data", [{}])[0]
                    if isinstance(result, dict):
                        prob = result.get("phishing_probability", 0.0)
                        conf = result.get("confidence", 0.6)
                        return float(prob), float(conf)
        except Exception as e:
            logger.warning(f"HF Space error: {e}, fallback ke Inference API")

    # Fallback ke HuggingFace Inference API
    if not HUGGINGFACE_API_KEY:
        return 0.0, 0.0
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                HF_MODEL_URL,
                headers={"Authorization": f"Bearer {HUGGINGFACE_API_KEY}"},
                json={"inputs": text[:512]},
            )
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and len(data) > 0:
                    results = data[0] if isinstance(data[0], list) else data
                    for item in results:
                        if "PHISHING" in item.get("label", "").upper():
                            return item["score"], item["score"]
                        elif "SAFE" in item.get("label", "").upper() or "LEGITIMATE" in item.get("label", "").upper():
                            return 1 - item["score"], item["score"]
    except Exception as e:
        logger.warning(f"HuggingFace Inference API error: {e}")
    return 0.0, 0.0


def get_nlp_pipeline():
    if HF_SPACE_URL:
        return "huggingface_space"
    if HUGGINGFACE_API_KEY:
        return "huggingface_api"
    return "fallback"


# ── Keyword banks ─────────────────────────────────────────────────────────────

URGENCY_PATTERNS = [
    r"\bsegera\b", r"\bsekarang\b", r"\burgent\b", r"\bmendesak\b",
    r"\bhours?\b", r"\bjam lagi\b", r"\bexpir", r"\bdeadline\b",
    r"\bsuspend", r"\bblokir", r"\bdibekukan\b", r"\bterbatas\b",
    r"\bimited time\b", r"\bact now\b", r"\b24 jam\b", r"\b48 jam\b",
    r"\bharus segera\b", r"\bjangan terlambat\b", r"\bsebelum\b",
    r"\bwaktu terbatas\b", r"\bberakhir\b", r"\bkadaluarsa\b",
]

THREAT_PATTERNS = [
    r"\bditutup\b", r"\bakan dihapus\b", r"\bhilang\b", r"\bdenda\b",
    r"\bpenalti\b", r"\bblacklist\b", r"\bdisuspend\b", r"\bterancam\b",
    r"\bpelanggaran\b", r"\bhukum\b", r"\bpolisi\b", r"\bdiblokir\b",
    r"\bpemblokiran\b", r"\bnonaktif\b", r"\bditangguhkan\b",
    r"\bdihapus permanen\b", r"\bditutup permanen\b", r"\bverifikasi\b",
    r"\baktivitas mencurigakan\b", r"\btidak sah\b", r"\bilegal\b",
]

REWARD_PATTERNS = [
    r"\bmenang\b", r"\bhadiah\b", r"\bgratis\b", r"\bbonus\b",
    r"\bcashback\b", r"\bdiskon\b", r"\bprize\b", r"\bwinner\b",
    r"\blottery\b", r"\bgiveaway\b", r"\bterpilih\b", r"\bselamat\b",
    r"\bberuntung\b", r"\bundian\b", r"\bvoucher\b", r"\breward\b",
    r"\bjuta rupiah\b", r"\bjuta\b", r"\bmendapatkan hadiah\b",
]

SUSPICIOUS_PHRASES_ID = [
    "klik link berikut", "verifikasi akun anda", "segera konfirmasi",
    "kata sandi", "PIN ATM", "kode OTP", "nomor kartu",
    "transfer sekarang", "hubungi kami segera", "kemenangan anda",
    "hadiah senilai", "akun anda diblokir", "login sekarang",
    "update data", "perbarui informasi", "konfirmasi identitas",
    "internet banking", "mobile banking", "masukkan password",
    "masukkan username", "verifikasi data", "klik di sini",
    "akun akan ditutup", "ditutup permanen", "aktivitas mencurigakan",
    "hubungi customer service", "segera verifikasi", "akun diblokir",
    "dalam 24 jam", "dalam 48 jam", "kode otp anda",
]


def _count_pattern_hits(text: str, patterns: List[str]) -> Tuple[float, List[str]]:
    hits = []
    text_lower = text.lower()
    for p in patterns:
        if re.search(p, text_lower):
            hits.append(p.strip(r"\b"))
    score = min(len(hits) / max(len(patterns) * 0.3, 1), 1.0)
    return score, hits


def _extract_links(text: str) -> List[str]:
    url_pattern = re.compile(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    )
    return url_pattern.findall(text)


def _detect_language(text: str) -> str:
    id_markers = ["dan", "yang", "untuk", "atau", "dengan", "dari", "ke", "di", "ini"]
    id_count = sum(1 for w in id_markers if f" {w} " in text.lower())
    return "id" if id_count >= 3 else "en"


def analyze_text(text: str) -> NLPResult:
    urgency_score, urgency_hits = _count_pattern_hits(text, URGENCY_PATTERNS)
    threat_score, threat_hits = _count_pattern_hits(text, THREAT_PATTERNS)
    reward_score, reward_hits = _count_pattern_hits(text, REWARD_PATTERNS)

    suspicious_phrases = [
        phrase for phrase in SUSPICIOUS_PHRASES_ID
        if phrase.lower() in text.lower()
    ]
    suspicious_phrases += urgency_hits[:3] + threat_hits[:3] + reward_hits[:2]

    links = _extract_links(text)
    lang = _detect_language(text)

    neg_count = len(urgency_hits) + len(threat_hits)
    pos_count = len(reward_hits)
    if neg_count > pos_count:
        sentiment = "negative"
    elif pos_count > 0:
        sentiment = "positive"
    else:
        sentiment = "neutral"

    return NLPResult(
        urgency_score=round(urgency_score, 3),
        threat_score=round(threat_score, 3),
        reward_score=round(reward_score, 3),
        link_count=len(links),
        suspicious_phrases=list(set(suspicious_phrases))[:10],
        sentiment=sentiment,
        language=lang,
    )


def nlp_model_score(text: str) -> Tuple[float, float]:
    import asyncio
    pipeline = get_nlp_pipeline()

    if pipeline in ("huggingface_space", "huggingface_api"):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, _call_hf_api(text))
                    return future.result(timeout=25)
            else:
                return loop.run_until_complete(_call_hf_api(text))
        except Exception as e:
            logger.error(f"HF API call failed: {e}")

    result = analyze_text(text)
    raw = (result.urgency_score * 0.4 +
           result.threat_score * 0.35 +
           result.reward_score * 0.25)
    return raw, 0.6