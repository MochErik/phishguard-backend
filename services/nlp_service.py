"""
NLP Engine — Phishing Text Classifier
Fallback: rule-based keyword scoring
"""
import re
from typing import List, Tuple
from loguru import logger
from models.schemas import NLPResult

_pipeline = None


def get_nlp_pipeline():
    return "fallback"


# ── Keyword banks ─────────────────────────────────────────────────────────────

URGENCY_PATTERNS = [
    r"\bsegera\b", r"\bsekarang\b", r"\burgent\b", r"\bmendesak\b",
    r"\bhours?\b", r"\bjam lagi\b", r"\bexpir", r"\bdeadline\b",
    r"\bsuspend", r"\bblokir", r"\bdibekukan\b", r"\bterbatas\b",
    r"\bimited time\b", r"\bact now\b",
]

THREAT_PATTERNS = [
    r"\bditutup\b", r"\bakan dihapus\b", r"\bhilang\b", r"\bdenda\b",
    r"\bpenalti\b", r"\bblacklist\b", r"\bdisuspend\b", r"\bterancam\b",
    r"\bpelanggaran\b", r"\bhukum\b", r"\bpolisi\b",
]

REWARD_PATTERNS = [
    r"\bmenang\b", r"\bhadiah\b", r"\bgratis\b", r"\bbonus\b",
    r"\bcashback\b", r"\bdiskon\b", r"\bprize\b", r"\bwinner\b",
    r"\blottery\b", r"\bgiveaway\b", r"\bterpilih\b",
]

SUSPICIOUS_PHRASES_ID = [
    "klik link berikut", "verifikasi akun anda", "segera konfirmasi",
    "data anda", "kata sandi", "PIN ATM", "kode OTP", "nomor kartu",
    "transfer sekarang", "hubungi kami segera", "kemenangan anda",
    "hadiah senilai", "akun anda diblokir", "login sekarang",
    "update data", "perbarui informasi", "konfirmasi identitas",
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
    pipeline = get_nlp_pipeline()

    if pipeline == "fallback" or pipeline is None:
        result = analyze_text(text)
        raw = (result.urgency_score * 0.4 +
               result.threat_score * 0.35 +
               result.reward_score * 0.25)
        return raw, 0.6

    try:
        out = pipeline(text[:512])[0]
        label = out["label"].upper()
        score = out["score"]
        prob = score if "PHISH" in label else (1 - score)
        return prob, score
    except Exception as e:
        logger.error(f"NLP inference error: {e}")
        return 0.0, 0.0