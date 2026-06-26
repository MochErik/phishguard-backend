from sqlalchemy import Column, String, Float, Integer, DateTime, Text, JSON, Boolean
from sqlalchemy.sql import func
from core.database import Base
import uuid


def gen_uuid():
    return str(uuid.uuid4())


class ScanResult(Base):
    """Stores every scan result for history & analytics."""
    __tablename__ = "scan_results"

    id = Column(String, primary_key=True, default=gen_uuid)
    scan_type = Column(String(20), nullable=False)  # url|email|sms|qr|web|document
    input_hash = Column(String(64))                 # SHA256 of raw input
    verdict = Column(String(20))                    # safe|suspicious|phishing
    risk_score = Column(Float)                      # 0.0 – 1.0
    confidence = Column(Float)                      # 0.0 – 1.0

    # JSON detail per analyser
    blacklist_hits = Column(JSON, default=list)
    nlp_features = Column(JSON, default=dict)
    url_features = Column(JSON, default=dict)
    ai_explanation = Column(JSON, default=dict)

    ip_address = Column(String(45))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class BlacklistEntry(Base):
    """Local blacklist cache (synced from PhishTank / OpenPhish / Google SB)."""
    __tablename__ = "blacklist_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), unique=True, index=True)
    domain = Column(String(255), index=True)
    source = Column(String(50))        # phishtank|openphish|google_sb|manual
    threat_type = Column(String(100))
    is_active = Column(Boolean, default=True)
    added_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)


class DailyStats(Base):
    """Aggregated daily stats per IP for rate limiting display."""
    __tablename__ = "daily_stats"

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(String(10), index=True)          # YYYY-MM-DD
    ip_address = Column(String(45), index=True)
    total_scans = Column(Integer, default=0)
    phishing_found = Column(Integer, default=0)
    safe_found = Column(Integer, default=0)
