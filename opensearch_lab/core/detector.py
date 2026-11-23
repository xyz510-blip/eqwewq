"""Smart target type auto-detection and normalization."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from opensearch_lab.core.known_entities import OFFICIAL_ID_HOTLINES
from opensearch_lab.core.models import TargetType

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".tiff", ".tif", ".bmp", ".gif"}

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$"
)
# Strict unambiguous crypto formats (avoid matching normal usernames)
BTC_RE = re.compile(r"^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})$")
ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
SOLANA_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")

BANK_ACCOUNT_RE = re.compile(
    r"^(?:rekening\s+|rek\.?\s+)?"
    r"(BCA|BRI|MANDIRI|BNI|BSI|SEABANK|JAGO|CIMB|CIMBNIAGA|PERMATA|DANAMON|BTN|OCBC|DANA|OVO|GOPAY|SHOPEEPAY)"
    r"[\s:\-/]+(\d[\d\s\-]{7,19}\d)$",
    re.IGNORECASE,
)

PHONE_CHARS_RE = re.compile(r"^\+?[\d\s\-().]{3,22}$")
FULL_NAME_RE = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ'.\-]*(?:\s+[A-Za-zÀ-ÖØ-öø-ÿ'.\-]+)+$")


def parse_target_type_hint(hint: str | None) -> TargetType | None:
    """Parse user-provided type flag into TargetType, or None for 'auto'."""
    if not hint or hint.strip().lower() in ("auto", ""):
        return None
    normalized = hint.strip().lower()
    aliases = {
        "user": TargetType.USERNAME,
        "username": TargetType.USERNAME,
        "handle": TargetType.USERNAME,
        "email": TargetType.EMAIL,
        "mail": TargetType.EMAIL,
        "phone": TargetType.PHONE,
        "tel": TargetType.PHONE,
        "hp": TargetType.PHONE,
        "wa": TargetType.PHONE,
        "domain": TargetType.DOMAIN,
        "host": TargetType.DOMAIN,
        "ip": TargetType.IP,
        "url": TargetType.URL,
        "link": TargetType.URL,
        "crypto": TargetType.CRYPTO_WALLET,
        "wallet": TargetType.CRYPTO_WALLET,
        "crypto_wallet": TargetType.CRYPTO_WALLET,
        "bank": TargetType.BANK_ACCOUNT,
        "rekening": TargetType.BANK_ACCOUNT,
        "rek": TargetType.BANK_ACCOUNT,
        "bank_account": TargetType.BANK_ACCOUNT,
        "image": TargetType.IMAGE_FILE,
        "image_file": TargetType.IMAGE_FILE,
        "img": TargetType.IMAGE_FILE,
        "name": TargetType.FULL_NAME,
        "full_name": TargetType.FULL_NAME,
        "person": TargetType.FULL_NAME,
    }
    return aliases.get(normalized)


def normalize_target(value: str, target_type: TargetType) -> str:
    """Normalize a target value according to its TargetType."""
    clean = value.strip()
    if target_type == TargetType.USERNAME:
        return clean.lstrip("@")
    if target_type == TargetType.EMAIL:
        return clean.lower()
    if target_type == TargetType.DOMAIN:
        clean = clean.lower().rstrip(".")
        if clean.startswith("www.") and clean.count(".") >= 2:
            # Keep bare registrable/host domain cleanly without stripping if intentionally queried
            return clean
        return clean
    if target_type == TargetType.URL:
        parsed = urlparse(clean)
        if not parsed.scheme:
            return f"http://{clean}"
        return clean
    if target_type == TargetType.PHONE:
        return re.sub(r"[\s\-()]", "", clean)
    if target_type == TargetType.BANK_ACCOUNT:
        m = BANK_ACCOUNT_RE.match(clean)
        if m:
            bank = m.group(1).upper()
            digits = re.sub(r"\D", "", m.group(2))
            return f"{bank}:{digits}"
        digits_only = re.sub(r"\D", "", clean)
        if digits_only and digits_only == clean:
            return f"BANK:{digits_only}"
        return " ".join(clean.split())
    if target_type == TargetType.FULL_NAME:
        return " ".join(clean.split())
    return clean


def detect_target_type(query: str, hint: str | None = None) -> tuple[TargetType, str]:
    """Detect the most likely TargetType and return (TargetType, normalized_value)."""
    raw = (query or "").strip()
    if not raw:
        return TargetType.UNKNOWN, ""

    forced = parse_target_type_hint(hint)
    if forced is not None:
        return forced, normalize_target(raw, forced)

    # 1. Local image file
    candidate_path = Path(raw)
    if candidate_path.suffix.lower() in IMAGE_EXTENSIONS and candidate_path.is_file():
        return TargetType.IMAGE_FILE, str(candidate_path.resolve())

    # 2. Explicit URL
    lower = raw.lower()
    if lower.startswith(("http://", "https://")):
        return TargetType.URL, normalize_target(raw, TargetType.URL)
    if "/" in raw and "." in raw.split("/", 1)[0] and " " not in raw:
        # e.g. bit.ly/abc123 or hadiah-dana.xyz/login
        host_part = raw.split("/", 1)[0]
        if DOMAIN_RE.match(host_part):
            return TargetType.URL, f"http://{raw}"

    # 3. IPv4 or IPv6
    try:
        ip_obj = ipaddress.ip_address(raw)
        return TargetType.IP, str(ip_obj)
    except ValueError:
        pass

    # 4. Email
    if EMAIL_RE.match(raw):
        return TargetType.EMAIL, normalize_target(raw, TargetType.EMAIL)

    # 5. Cryptocurrency wallet (BTC, ETH/EVM, TRON)
    if BTC_RE.match(raw) or ETH_RE.match(raw) or TRON_RE.match(raw):
        return TargetType.CRYPTO_WALLET, raw

    # 5.5 Bank account with explicit Indonesian bank/ewallet prefix (e.g., BCA 1234567890)
    if BANK_ACCOUNT_RE.match(raw):
        return TargetType.BANK_ACCOUNT, normalize_target(raw, TargetType.BANK_ACCOUNT)

    # 6. Phone number (official hotlines, +, 08, 628, 812..., or phone punctuation with 8-15 digits)
    if PHONE_CHARS_RE.match(raw):
        digits_only = re.sub(r"\D", "", raw)
        if digits_only in OFFICIAL_ID_HOTLINES:
            return TargetType.PHONE, digits_only
        if 8 <= len(digits_only) <= 15:
            if raw.startswith("+") or digits_only.startswith(("08", "628", "02")) or any(
                c in raw for c in (" ", "-", "(", ")")
            ):
                return TargetType.PHONE, normalize_target(raw, TargetType.PHONE)
            # Plain 9-15 digit string starting with 0, 62, or missing leading 0 (e.g., 81234567890)
            if digits_only.startswith(("0", "62")) and len(digits_only) >= 9:
                return TargetType.PHONE, normalize_target(raw, TargetType.PHONE)
            if digits_only.startswith("8") and 9 <= len(digits_only) <= 12:
                return TargetType.PHONE, normalize_target(raw, TargetType.PHONE)

    # 7. Domain
    if DOMAIN_RE.match(raw):
        return TargetType.DOMAIN, normalize_target(raw, TargetType.DOMAIN)

    # 8. Full Name (multi-word alphabetic name)
    if FULL_NAME_RE.match(raw):
        return TargetType.FULL_NAME, normalize_target(raw, TargetType.FULL_NAME)

    # 9. Fallback: Username (strip leading @ if any)
    if " " not in raw and len(raw) <= 64:
        return TargetType.USERNAME, normalize_target(raw, TargetType.USERNAME)

    return TargetType.FULL_NAME, normalize_target(raw, TargetType.FULL_NAME)
