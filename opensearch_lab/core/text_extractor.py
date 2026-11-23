"""Bulk chat/SMS/DM scam modus analyzer and IOC extractor."""

from __future__ import annotations

import re
from typing import Any

from opensearch_lab.core.detector import BTC_RE, ETH_RE, TRON_RE
from opensearch_lab.core.known_entities import is_trusted_domain
from opensearch_lab.core.risk_scorer import RiskScorer
from opensearch_lab.modules.scam_intel import UrlPhishingModule

URL_EXTRACT_RE = re.compile(r"https?://[^\s<>\"'()]+", re.IGNORECASE)
BARE_URL_RE = re.compile(
    r"\b(?:bit\.ly|tinyurl\.com|s\.id|cutt\.ly|rb\.gy|shorturl\.at)/[A-Za-z0-9_\-]+\b",
    re.IGNORECASE,
)
EMAIL_EXTRACT_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,16}\b")
PHONE_EXTRACT_RE = re.compile(r"(?<!\d)(?:\+?62|0)8[\d\s\-]{7,13}\d(?!\d)")
INTL_PHONE_RE = re.compile(r"(?<!\d)\+[1-9]\d{7,14}(?!\d)")
BANK_EXTRACT_RE = re.compile(
    r"\b(?:rekening\s+|rek\.?\s+)?"
    r"(BCA|BRI|MANDIRI|BNI|BSI|SEABANK|JAGO|CIMB|PERMATA|DANAMON|BTN|OCBC)"
    r"[\s:\-/]+(\d[\d\s\-]{7,18}\d)\b",
    re.IGNORECASE,
)
CRYPTO_EXTRACT_RE = re.compile(r"\b(?:0x[a-fA-F0-9]{40}|T[1-9A-HJ-NP-Za-km-z]{33}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b")
TG_EXTRACT_RE = re.compile(r"(?:t\.me/|@)([A-Za-z0-9_]{4,32})\b", re.IGNORECASE)
APK_EXTRACT_RE = re.compile(r"\b[A-Za-z0-9_\-.]{2,64}\.apk\b", re.IGNORECASE)

SCAM_MODUS_RULES: list[dict[str, Any]] = [
    {
        "id": "fake_apk",
        "name": "Modus File .APK Berbahaya (Undangan / Kurir / Surat Tilang)",
        "points": 45,
        "severity": "critical",
        "keywords": (".apk", "undangan pernikahan", "foto paket", "resi paket", "surat tilang", "e-tilang", "tagihan bpjs"),
        "advice": "JANGAN PERNAH menginstal file .apk dari chat! File APK dipakai pencuri OTP m-banking & SMS.",
    },
    {
        "id": "bank_phishing",
        "name": "Modus Phishing Perbankan / DANA Kaget / Perubahan Tarif",
        "points": 35,
        "severity": "critical",
        "keywords": ("perubahan tarif", "tarif transaksi", "dana kaget", "klaim hadiah", "undian resmi", "blokir rekening", "aktivasi ulang"),
        "advice": "Bank resmi tidak pernah meminta PIN, OTP, CVV, atau klik link di luar domain resmi (.co.id / .id).",
    },
    {
        "id": "job_scam",
        "name": "Modus Job Scam / Tugas Like-Subscribe Berujung Deposit",
        "points": 30,
        "severity": "high",
        "keywords": ("tugas like", "subscribe", "komisi harian", "kerja paruh waktu", "deposit dulu", "top up saldo", "admin telegram", "mentor tugas"),
        "advice": "Lowongan tugas klik/like yang meminta top-up/deposit uang jaminan adalah penipuan berantai.",
    },
    {
        "id": "investment_scam",
        "name": "Modus Investasi Bodong / Titip Dana / Profit Pasti",
        "points": 30,
        "severity": "high",
        "keywords": ("titip dana", "profit pasti", "cuan pasti", "anti rugi", "garansi modal", "lipat ganda", "trading vip"),
        "advice": "Cek legalitas entitas di Kontak OJK 157 sebelum menyetor dana apa pun.",
    },
    {
        "id": "triangle_receipt",
        "name": "Modus Bukti Transfer Palsu / Penipuan Segitiga",
        "points": 25,
        "severity": "high",
        "keywords": ("bukti transfer", "sudah transfer", "salah transfer", "kembalikan kelebihan", "rekening berbeda", "dana tertahan"),
        "advice": "Selalu cek mutasi masuk langsung di aplikasi m-banking Anda, jangan percaya screenshot bukti transfer.",
    },
    {
        "id": "authority_impersonation",
        "name": "Modus Peniruan Aparat / OJK / Pajak / Bea Cukai",
        "points": 30,
        "severity": "high",
        "keywords": ("bea cukai", "barang tertahan", "denda tilang", "pihak kepolisian", "blokir nik", "pajak tertunggak", "kominfo"),
        "advice": "Instansi resmi tidak meminta transfer denda ke rekening pribadi atau e-wallet.",
    },
]

URGENCY_WORDS: tuple[str, ...] = (
    "segera",
    "sekarang juga",
    "hari ini terakhir",
    "dalam 1 jam",
    "akan diblokir",
    "hangus",
    "wajib klik",
    "jangan beritahu siapa",
    "rahasia",
)


class ScamTextAnalyzer:
    """Extracts IOCs and evaluates Indonesian/global scam modus patterns from raw chat/SMS/DM logs."""

    @classmethod
    def analyze_text(cls, text: str) -> dict[str, Any]:
        raw = (text or "").strip()
        if not raw:
            return {
                "scam_score": 0,
                "risk_level": "LOW",
                "matched_modi": [],
                "urgency_hits": [],
                "iocs": [],
                "recommendations": ["Masukkan teks pesan/chat mencurigakan untuk dianalisis."],
            }

        low = raw.lower()
        iocs: list[dict[str, str]] = []
        seen_iocs: set[tuple[str, str]] = set()

        def add_ioc(ioc_type: str, value: str, label: str) -> None:
            clean = value.strip().rstrip(".,;)")
            key = (ioc_type, clean.lower())
            if clean and key not in seen_iocs:
                seen_iocs.add(key)
                iocs.append({"type": ioc_type, "value": clean, "label": label})

        for u in URL_EXTRACT_RE.findall(raw):
            add_ioc("url", u, "Tautan / URL")
        for bu in BARE_URL_RE.findall(raw):
            add_ioc("url", f"https://{bu}", "URL Shortener")
        for em in EMAIL_EXTRACT_RE.findall(raw):
            add_ioc("email", em.lower(), "Alamat Email")
        for bank, acc in BANK_EXTRACT_RE.findall(raw):
            digits = re.sub(r"\D", "", acc)
            add_ioc("bank_account", f"{bank.upper()}:{digits}", f"Rekening {bank.upper()}")
        for ph in PHONE_EXTRACT_RE.findall(raw):
            norm_ph = re.sub(r"[\s\-]", "", ph)
            add_ioc("phone", norm_ph, "Nomor Telepon / WhatsApp")
        for iph in INTL_PHONE_RE.findall(raw):
            add_ioc("phone", iph, "Nomor Internasional")
        for cw in CRYPTO_EXTRACT_RE.findall(raw):
            if BTC_RE.match(cw) or ETH_RE.match(cw) or TRON_RE.match(cw):
                add_ioc("crypto_wallet", cw, "Crypto Wallet")
        for tg in TG_EXTRACT_RE.findall(raw):
            if tg.lower() not in {"here", "everyone", "channel", "joinchat"}:
                add_ioc("username", tg, "Handle / Username Telegram")
        for apk in APK_EXTRACT_RE.findall(raw):
            add_ioc("artifact", apk.strip(), "File Berbahaya (.apk)")

        matched_modi: list[dict[str, Any]] = []
        score = 0
        recommendations: list[str] = []

        for rule in SCAM_MODUS_RULES:
            hits = [kw for kw in rule["keywords"] if kw in low]
            if hits:
                score += int(rule["points"])
                matched_modi.append(
                    {
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "points": rule["points"],
                        "matched_keywords": hits,
                    }
                )
                recommendations.append(rule["advice"])

        urgency_hits = [u for u in URGENCY_WORDS if u in low]
        if urgency_hits:
            score += min(15, 5 * len(urgency_hits))
            recommendations.append("Pesan menggunakan teknik tekanan/urgensi psikologis agar korban panik tanpa verifikasi.")

        # Bonus if suspicious APK or URL shortener appears in message
        if any(i["type"] == "artifact" for i in iocs):
            score += 20
        if any(i["label"] == "URL Shortener" for i in iocs):
            score += 10

        # Run fast offline phishing heuristics on extracted URLs
        url_mod = UrlPhishingModule()
        from urllib.parse import urlparse
        for item in iocs:
            if item["type"] == "url":
                parsed_u = urlparse(item["value"])
                host_u = (parsed_u.hostname or "").lower()
                if host_u and not is_trusted_domain(host_u):
                    url_findings: list[Any] = []
                    url_mod._run_heuristics(item["value"], host_u, parsed_u, url_findings)
                    high_u = [f for f in url_findings if f.risk_delta >= 15]
                    if high_u:
                        score += min(30, sum(f.risk_delta for f in high_u))
                        recommendations.append(
                            f"Tautan mencurigakan '{item['value']}' memicu sinyal phishing: {high_u[0].title}."
                        )

        final_score = max(0, min(100, score))
        level = RiskScorer.score_to_level(final_score)

        if not recommendations:
            recommendations.append(
                "Tidak ditemukan frasa modus scam klasik secara eksplisit, tetap pindai tautan/nomor/rekening yang diekstrak."
            )

        return {
            "scam_score": final_score,
            "risk_level": level,
            "matched_modi": matched_modi,
            "urgency_hits": urgency_hits,
            "iocs": iocs,
            "recommendations": recommendations,
        }
