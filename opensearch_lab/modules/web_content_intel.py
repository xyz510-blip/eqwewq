"""Live HTML web content analyzer: phishing kits, OTP/PIN forms, Telegram bot exfil, & contact harvester."""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.correlator import make_entity_id
from opensearch_lab.core.detector import BTC_RE, ETH_RE, TRON_RE
from opensearch_lab.core.known_entities import is_trusted_domain
from opensearch_lab.core.models import (
    EntityEdge,
    EntityNode,
    Finding,
    ModuleResult,
    Severity,
    TargetType,
)

PARKING_SIGNATURES: tuple[str, ...] = (
    "sedoparking",
    "bodis.com",
    "dan.com",
    "afternic",
    "hugedomains",
    "buy this domain",
    "this domain is for sale",
    "domain is parked",
)

SENSITIVE_FORM_FIELDS: tuple[str, ...] = (
    "otp",
    "pin",
    "cvv",
    "cvc",
    "kartu",
    "card_number",
    "cardnumber",
    "rekening",
    "no_rek",
    "norek",
    "nik",
    "ktp",
    "ibu kandung",
    "mother",
    "seed phrase",
    "mnemonic",
    "passphrase",
    "kata sandi",
    "password",
)

TITLE_BRAND_CLAIMS: dict[str, tuple[str, ...]] = {
    "BCA": ("bank bca", "mybca", "klikbca", "halo bca"),
    "BRI": ("bank bri", "brimo", "bri mobile", "internet banking bri"),
    "MANDIRI": ("bank mandiri", "livin by mandiri", "livin' by mandiri"),
    "BNI": ("bank bni", "bni mobile", "wondr by bni"),
    "BSI": ("bank syariah indonesia", "bsi mobile"),
    "DANA": ("dana kaget", "dana indonesia", "aplikasi dana", "klaim dana"),
    "OVO": ("ovo indonesia", "ovo cash"),
    "SHOPEE": ("shopee indonesia", "shopeepay", "shopee hadiah"),
    "OJK": ("otoritas jasa keuangan",),
    "PAJAK": ("direktorat jenderal pajak", "djp online"),
}

TG_BOT_TOKEN_RE = re.compile(r"api\.telegram\.org/bot\d{6,}:[A-Za-z0-9_\-]{20,}", re.IGNORECASE)
TG_EXFIL_HINT_RE = re.compile(r"sendMessage.*chat_id|chat_id.*sendMessage", re.IGNORECASE | re.DOTALL)
WA_LINK_RE = re.compile(r"(?:wa\.me/|api\.whatsapp\.com/send\?[^\"'\s]*phone=)(\d{8,15})", re.IGNORECASE)
TG_LINK_RE = re.compile(r"t\.me/([A-Za-z0-9_]{4,32})", re.IGNORECASE)
EMAIL_FIND_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,16}")


class WebContentAnalyzerModule(BaseOSINTModule):
    """Inspects live HTML pages for phishing forms, Telegram exfil kits, brand spoofing, and contacts."""

    name = "web_content"
    display_name = "Web Content & Phishing Kit Analyzer"
    description = "Menganalisis HTML halaman untuk mendeteksi form curi OTP/PIN/KTP, kit bot Telegram penipu, dan kontak WA/TG tersembunyi."
    category = "anti_scam"
    supported_targets = {TargetType.URL, TargetType.DOMAIN}

    async def run(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
    ) -> ModuleResult:
        started = time.perf_counter()
        findings: list[Finding] = []
        entities: list[EntityNode] = []
        edges: list[EntityEdge] = []
        pivots: list[dict[str, str]] = []
        root_id = make_entity_id(target_type.value, target)

        full_url = target if target_type == TargetType.URL else f"https://{target}"
        parsed = urlparse(full_url)
        host = (parsed.hostname or target).lower().rstrip(".")

        html_text = ""
        final_url = full_url
        try:
            async with ctx.http_session.get(full_url, timeout=8, allow_redirects=True) as resp:
                final_url = str(resp.url)
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if resp.status >= 400 or (ctype and "html" not in ctype and "text" not in ctype and "javascript" not in ctype):
                    elapsed = int((time.perf_counter() - started) * 1000)
                    return ModuleResult(
                        module_name=self.name,
                        display_name=self.display_name,
                        status="partial",
                        duration_ms=elapsed,
                        summary=f"Halaman mengembalikan HTTP {resp.status} ({ctype or 'unknown'}).",
                    )
                raw = await resp.content.read(262144)
                html_text = raw.decode("utf-8", errors="ignore")
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                status="partial",
                duration_ms=elapsed,
                summary=f"Konten HTML tidak dapat diambil ({type(exc).__name__}).",
            )

        self.analyze_html(
            html_text=html_text,
            page_url=final_url,
            host=(urlparse(final_url).hostname or host).lower(),
            root_id=root_id,
            findings=findings,
            entities=entities,
            edges=edges,
            pivots=pivots,
        )

        elapsed = int((time.perf_counter() - started) * 1000)
        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            status="ok",
            duration_ms=elapsed,
            findings=findings,
            entities=entities,
            edges=edges,
            summary=f"Inspeksi konten HTML selesai ({len(findings)} temuan).",
            pivot_candidates=pivots,
        )

    def analyze_html(
        self,
        html_text: str,
        page_url: str,
        host: str,
        root_id: str,
        findings: list[Finding],
        entities: list[EntityNode],
        edges: list[EntityEdge],
        pivots: list[dict[str, str]],
    ) -> None:
        """Analyze raw HTML string; separated for clean unit testing and direct reuse."""
        if not html_text.strip():
            return

        low_html = html_text.lower()
        soup = BeautifulSoup(html_text, "html.parser")
        title_tag = soup.title.string.strip() if soup.title and soup.title.string else ""
        og_title_el = soup.find("meta", attrs={"property": "og:title"})
        og_title = str(og_title_el.get("content", "")).strip() if og_title_el else ""
        effective_title = title_tag or og_title

        if effective_title:
            findings.append(
                Finding(
                    source=self.name,
                    category="web_metadata",
                    title="Judul Halaman Web (HTML Title)",
                    value=effective_title[:160],
                    url=page_url,
                    severity=Severity.INFO,
                    confidence=0.95,
                )
            )

        # 1. Domain parking detection
        if any(sig in low_html for sig in PARKING_SIGNATURES):
            findings.append(
                Finding(
                    source=self.name,
                    category="domain_parking",
                    title="Halaman Domain Parkir / Dijual",
                    value="Domain menampilkan halaman parkir atau penawaran jual domain (bukan situs phishing aktif).",
                    severity=Severity.INFO,
                    confidence=0.9,
                    risk_delta=0,
                )
            )
            return

        trusted = is_trusted_domain(host)

        # 2. Telegram Bot Phishing Kit detection
        bot_match = TG_BOT_TOKEN_RE.search(html_text)
        if bot_match or (TG_EXFIL_HINT_RE.search(html_text) and "telegram" in low_html):
            masked = bot_match.group(0)[:36] + "..." if bot_match else "api.telegram.org sendMessage + chat_id"
            findings.append(
                Finding(
                    source=self.name,
                    category="phishing_kit",
                    title="Terdeteksi Phishing Kit Eksfiltrasi Telegram Bot!",
                    value=f"Kode halaman mengirim input korban ke bot Telegram ({masked}) — bukti kuat situs phishing!",
                    url=page_url,
                    severity=Severity.CRITICAL,
                    confidence=0.98,
                    risk_delta=40,
                    signal_tier="confirmed_threat",
                )
            )

        if not trusted:
            # 3. Title Brand Mismatch
            title_low = effective_title.lower()
            claimed_brands = [
                brand
                for brand, phrases in TITLE_BRAND_CLAIMS.items()
                if any(ph in title_low for ph in phrases)
            ]
            if claimed_brands:
                findings.append(
                    Finding(
                        source=self.name,
                        category="brand_impersonation",
                        title=f"Judul Halaman Mengklaim Merek Resmi ({', '.join(claimed_brands)})",
                        value=f"Judul '{effective_title[:100]}' mengatasnamakan {', '.join(claimed_brands)} pada domain non-resmi '{host}'!",
                        url=page_url,
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        risk_delta=35,
                        signal_tier="confirmed_threat",
                    )
                )

            # 4. Credential / Banking / OTP Harvesting Form Detector
            forms = soup.find_all("form")
            if forms:
                matched_fields: set[str] = set()
                has_password_input = False
                for form in forms:
                    form_blob = form.get_text(" ", strip=True).lower()
                    for inp in form.find_all(["input", "textarea", "select"]):
                        itype = str(inp.get("type") or "").lower()
                        if itype == "password":
                            has_password_input = True
                        attrs_txt = " ".join(
                            str(inp.get(a) or "") for a in ("name", "id", "placeholder", "aria-label")
                        ).lower()
                        combined_inp = f"{form_blob} {attrs_txt}"
                        for kw in SENSITIVE_FORM_FIELDS:
                            if kw in combined_inp:
                                matched_fields.add(kw)

                high_risk_bank_fields = matched_fields & {
                    "otp", "pin", "cvv", "cvc", "kartu", "rekening", "no_rek", "norek",
                    "nik", "ktp", "ibu kandung", "seed phrase", "mnemonic", "passphrase",
                }
                if high_risk_bank_fields or (has_password_input and claimed_brands):
                    findings.append(
                        Finding(
                            source=self.name,
                            category="credential_harvesting",
                            title="Form Pengumpulan Data Sensitif / Perbankan / OTP",
                            value=f"Form meminta input sensitif ({', '.join(sorted(matched_fields)[:8])}) pada domain non-resmi '{host}'.",
                            url=page_url,
                            severity=Severity.CRITICAL,
                            confidence=0.94,
                            risk_delta=35,
                            signal_tier="confirmed_threat",
                            metadata={"fields": sorted(matched_fields)},
                        )
                    )

        # 5. Embedded Scammer Contact Harvester (WA, TG, Emails, Crypto Wallets)
        for wa_digits in sorted(set(WA_LINK_RE.findall(html_text)))[:5]:
            wid = make_entity_id("phone", f"+{wa_digits}")
            entities.append(EntityNode(id=wid, label=f"+{wa_digits}", entity_type="phone"))
            edges.append(EntityEdge(source=root_id, target=wid, relation="embeds_whatsapp"))
            pivots.append({"value": f"+{wa_digits}", "type": "phone", "reason": "Nomor WhatsApp tertanam di halaman web"})
            findings.append(
                Finding(
                    source=self.name,
                    category="embedded_contact",
                    title="Nomor WhatsApp Tertanam di Halaman",
                    value=f"+{wa_digits}",
                    url=f"https://wa.me/{wa_digits}",
                    severity=Severity.INFO,
                    confidence=0.92,
                )
            )

        for tg_handle in sorted(set(TG_LINK_RE.findall(html_text)))[:5]:
            if tg_handle.lower() in {"share", "joinchat", "s"}:
                continue
            tid = make_entity_id("username", tg_handle)
            entities.append(EntityNode(id=tid, label=tg_handle, entity_type="username"))
            edges.append(EntityEdge(source=root_id, target=tid, relation="embeds_telegram"))
            pivots.append({"value": tg_handle, "type": "username", "reason": "Akun/grup Telegram tertanam di halaman web"})

        for em in sorted(set(EMAIL_FIND_RE.findall(html_text)))[:5]:
            if em.lower().endswith((".png", ".jpg", ".svg", ".webp", ".css", ".js")):
                continue
            eid = make_entity_id("email", em.lower())
            entities.append(EntityNode(id=eid, label=em.lower(), entity_type="email"))
            edges.append(EntityEdge(source=root_id, target=eid, relation="embeds_email"))
            pivots.append({"value": em.lower(), "type": "email", "reason": "Email kontak tertanam di halaman web"})

        # Check crypto wallets inside HTML
        wallet_hits = sorted(
            set(re.findall(r"\b(?:0x[a-fA-F0-9]{40}|T[1-9A-HJ-NP-Za-km-z]{33}|bc1[ac-hj-np-z02-9]{11,71})\b", html_text))
        )
        for token in wallet_hits[:3]:
            if BTC_RE.match(token) or ETH_RE.match(token) or TRON_RE.match(token):
                cid = make_entity_id("crypto_wallet", token)
                entities.append(EntityNode(id=cid, label=token, entity_type="crypto_wallet"))
                edges.append(EntityEdge(source=root_id, target=cid, relation="embeds_wallet"))
                pivots.append({"value": token, "type": "crypto_wallet", "reason": "Wallet kripto tertanam di halaman web"})
