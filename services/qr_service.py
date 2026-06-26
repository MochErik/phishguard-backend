"""
QR Code Decoder
Decode QR dari gambar upload, ekstrak URL/teks, lalu kirim ke URL analyzer
"""
import io
from typing import Optional
from loguru import logger


def decode_qr(image_bytes: bytes) -> Optional[str]:
    """
    Decode QR code dari bytes gambar.
    Primary: pyzbar (fast, akurat)
    Fallback: OpenCV (jika pyzbar gagal)
    """
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as pyzbar_decode

        img = Image.open(io.BytesIO(image_bytes))
        results = pyzbar_decode(img)
        if results:
            return results[0].data.decode("utf-8", errors="ignore")
    except ImportError:
        logger.warning("pyzbar not installed, trying OpenCV")
    except Exception as e:
        logger.warning(f"pyzbar decode error: {e}")

    # Fallback OpenCV
    try:
        import cv2
        import numpy as np

        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)
        if data:
            return data
    except Exception as e:
        logger.warning(f"OpenCV QR decode error: {e}")

    return None


def is_url(text: str) -> bool:
    return text.strip().lower().startswith(("http://", "https://", "www."))
