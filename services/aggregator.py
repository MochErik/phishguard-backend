"""
Risk Score Aggregator
Menggabungkan hasil blacklist, heuristic URL, NLP, dan AI model
menjadi satu skor akhir + verdict.
"""
from typing import Optional
from models.schemas import (
    Verdict, BlacklistResult, URLFeatures,
    NLPResult, AIAnalysis, ScanType
)

# Bobot per komponen (total harus = 1.0)
WEIGHTS = {
    "blacklist":  0.45,   # Blacklist hit punya bobot tertinggi
    "url_heuristic": 0.20,
    "nlp":        0.20,
    "ai_model":   0.15,
}


def aggregate(
    scan_type: ScanType,
    blacklist: Optional[BlacklistResult] = None,
    url_heuristic_score: Optional[float] = None,   # 0-1
    nlp_result: Optional[NLPResult] = None,
    ai_score: Optional[float] = None,              # 0-1
) -> dict:
    """
    Return dict: {risk_score (0-100), verdict, confidence, summary, recommendations}
    """
    components = {}

    # 1. Blacklist — jika ada hit langsung phishing
    if blacklist and blacklist.hit:
        components["blacklist"] = 1.0
    elif blacklist:
        components["blacklist"] = 0.0

    # 2. URL heuristic
    if url_heuristic_score is not None:
        components["url_heuristic"] = url_heuristic_score

    # 3. NLP
    if nlp_result:
        nlp_score = (
            nlp_result.urgency_score * 0.35 +
            nlp_result.threat_score  * 0.40 +
            nlp_result.reward_score  * 0.25
        )
        # Banyak link mencurigakan → boost
        if nlp_result.link_count > 3:
            nlp_score = min(nlp_score + 0.15, 1.0)
        components["nlp"] = nlp_score

    # 4. AI model score
    if ai_score is not None:
        components["ai_model"] = ai_score

    if not components:
        return _build_result(0.0, 0.3, blacklist)

    # Weighted average hanya dari komponen yang tersedia
    total_weight = sum(WEIGHTS[k] for k in components)
    raw = sum(WEIGHTS[k] * v for k, v in components.items()) / total_weight

    # Confidence naik seiring banyaknya komponen yang tersedia
    confidence = min(0.5 + len(components) * 0.12, 0.95)

    # Override: blacklist hit = always phishing
    if blacklist and blacklist.hit:
        raw = max(raw, 0.85)
        confidence = 0.98

    return _build_result(raw, confidence, blacklist, components, nlp_result)


def _build_result(raw: float, confidence: float,
                  blacklist=None, components=None, nlp_result=None) -> dict:
    risk_score = round(raw * 100, 1)

    if raw >= 0.70:
        verdict = Verdict.phishing
        summary = "Konten ini terdeteksi sebagai phishing. Jangan klik link atau berikan informasi apapun."
        recs = [
            "Jangan klik link atau tombol apapun dalam pesan ini",
            "Laporkan ke pihak berwenang atau platform asal",
            "Hapus pesan dan blokir pengirim",
            "Jika sudah terlanjur klik, segera ganti password dan pantau rekening",
        ]
    elif raw >= 0.40:
        verdict = Verdict.suspicious
        summary = "Konten ini mencurigakan. Verifikasi keasliannya sebelum mengambil tindakan."
        recs = [
            "Jangan berikan data sensitif (password, OTP, nomor kartu)",
            "Hubungi institusi terkait melalui kanal resmi untuk memverifikasi",
            "Periksa URL dengan teliti sebelum mengklik",
            "Abaikan jika Anda tidak sedang mengharapkan pesan ini",
        ]
    else:
        verdict = Verdict.safe
        summary = "Konten ini terlihat aman berdasarkan analisis kami."
        recs = [
            "Tetap berhati-hati dan tidak membagikan data sensitif secara sembarangan",
            "Pastikan selalu menggunakan koneksi HTTPS saat bertransaksi",
        ]

    if blacklist and blacklist.hit:
        recs.insert(0, f"⚠️ Terdeteksi di blacklist: {', '.join(blacklist.sources)}")

    if nlp_result and nlp_result.suspicious_phrases:
        phrases = nlp_result.suspicious_phrases[:3]
        recs.append(f"Frasa mencurigakan ditemukan: '{', '.join(phrases)}'")

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "confidence": round(confidence, 3),
        "summary": summary,
        "recommendations": recs,
        "component_scores": components or {},
    }
