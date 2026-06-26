"""
URL Feature Extractor + Blacklist Checker
Menggunakan free APIs: Google Safe Browsing, PhishTank, OpenPhish
"""
import re
import math
import asyncio
import hashlib
import tldextract
import httpx
from typing import Optional
from urllib.parse import urlparse, unquote
from loguru import logger
from core.config import settings
from models.schemas import URLFeatures, BlacklistResult


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "update",
    "confirm", "banking", "paypal", "apple", "google", "microsoft",
    "password", "credential", "wallet", "crypto", "winner", "prize",
    "free", "urgent", "suspended", "limited", "expire", "click",
    "ebay", "amazon", "netflix", "bri", "bca", "mandiri", "bni",
    "shopee", "tokopedia", "gojek", "grab", "dana", "ovo", "gopay",
]


def url_entropy(url: str) -> float:
    """Shannon entropy — URL acak/encoded punya entropy tinggi."""
    if not url:
        return 0.0
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    n = len(url)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def extract_features(url: str) -> URLFeatures:
    """Extract heuristic features dari URL."""
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    decoded = unquote(url.lower())

    suspicious = [kw for kw in SUSPICIOUS_KEYWORDS if kw in decoded]

    # IP-based URL detection
    ip_pattern = re.compile(
        r"(\d{1,3}\.){3}\d{1,3}"
    )

    return URLFeatures(
        domain=ext.registered_domain or parsed.netloc,
        tld=ext.suffix or "",
        subdomain=ext.subdomain or None,
        path_length=len(parsed.path),
        has_ip=bool(ip_pattern.search(parsed.netloc)),
        has_at_sign="@" in url,
        has_double_slash=url.count("//") > 1,
        has_dash_in_domain="-" in (ext.domain or ""),
        https=parsed.scheme == "https",
        domain_age_days=None,  # enriched async below
        suspicious_keywords=suspicious,
        redirect_count=0,
        url_entropy=round(url_entropy(url), 4),
    )


async def check_google_safe_browsing(url: str) -> Optional[BlacklistResult]:
    """
    Google Safe Browsing API v4 — 10.000 req/hari GRATIS.
    Daftar: https://console.cloud.google.com/
    """
    if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
        return None

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={settings.GOOGLE_SAFE_BROWSING_API_KEY}"
    )
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(endpoint, json=body)
            data = r.json()
            if "matches" in data and data["matches"]:
                m = data["matches"][0]
                return BlacklistResult(
                    hit=True,
                    sources=["google_safe_browsing"],
                    threat_type=m.get("threatType", "UNKNOWN"),
                )
    except Exception as e:
        logger.warning(f"Google SB error: {e}")
    return BlacklistResult(hit=False)


async def check_phishtank(url: str) -> Optional[BlacklistResult]:
    """
    PhishTank API — gratis, ~3400 req/hari tanpa key, lebih banyak dengan key.
    Daftar: https://www.phishtank.com/api_register.php
    """
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    data = {
        "url": url,
        "format": "json",
        "app_key": settings.PHISHTANK_API_KEY,
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(endpoint, data=data)
            result = r.json()
            if result.get("results", {}).get("in_database"):
                return BlacklistResult(
                    hit=result["results"].get("valid", False),
                    sources=["phishtank"],
                    threat_type="phishing",
                )
    except Exception as e:
        logger.warning(f"PhishTank error: {e}")
    return BlacklistResult(hit=False)


async def check_blacklists(url: str) -> BlacklistResult:
    """Cek semua blacklist secara paralel."""
    results = await asyncio.gather(
        check_google_safe_browsing(url),
        check_phishtank(url),
        return_exceptions=True,
    )

    all_sources = []
    threat = None
    for r in results:
        if isinstance(r, BlacklistResult) and r.hit:
            all_sources.extend(r.sources)
            threat = threat or r.threat_type

    return BlacklistResult(
        hit=bool(all_sources),
        sources=all_sources,
        threat_type=threat,
    )


def heuristic_score(features: URLFeatures) -> float:
    score = 0.0

    if features.has_ip:
        score += 0.40
    if features.has_at_sign:
        score += 0.30
    if features.has_double_slash:
        score += 0.20
    if not features.https:
        score += 0.20
    if features.has_dash_in_domain:
        score += 0.15
    if features.path_length > 100:
        score += 0.15
    if features.url_entropy > 4.0:
        score += 0.15
    if len(features.suspicious_keywords) >= 3:
        score += 0.30
    elif len(features.suspicious_keywords) == 2:
        score += 0.20
    elif len(features.suspicious_keywords) == 1:
        score += 0.10
    if features.subdomain and features.subdomain.count(".") > 1:
        score += 0.15

    return min(score, 1.0)