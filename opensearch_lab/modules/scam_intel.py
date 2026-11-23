"""Anti-scam heuristics, phishing URL unshortening, public threat feeds, and OSINT dork generator."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urljoin, urlparse

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.correlator import make_entity_id
from opensearch_lab.core.domain_utils import (
    extract_registrable_domain,
    levenshtein_distance,
    normalize_leet,
    subdomain_depth,
)
from opensearch_lab.core.known_entities import BRAND_FALSE_POSITIVE_WORDS, is_trusted_domain
from opensearch_lab.core.models import (
    EntityEdge,
    EntityNode,
    Finding,
    ModuleResult,
    Severity,
    TargetType,
)

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq",
    "buzz", "loan", "vip", "icu", "work", "sbs", "cfd", "shop", "live", "rest",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "s.id", "cutt.ly", "t.co",
    "rb.gy", "shorturl.at", "ow.ly", "is.gd", "tiny.cc", "rebrand.ly",
}

# Brand -> official allowed domain suffixes
PROTECTED_BRANDS: dict[str, set[str]] = {
    "bca": {"bca.co.id", "klikbca.com"},
    "bri": {"bri.co.id", "brimo.bri.co.id"},
    "bni": {"bni.co.id"},
    "mandiri": {"bankmandiri.co.id", "livin.co.id"},
    "bsi": {"bankbsi.co.id"},
    "dana": {"dana.id"},
    "ovo": {"ovo.id"},
    "gopay": {"gopay.co.id", "gojek.com"},
    "shopee": {"shopee.co.id", "shopee.com"},
    "shopeepay": {"shopeepay.co.id", "shopee.co.id"},
    "tokopedia": {"tokopedia.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "telegram": {"telegram.org", "t.me"},
    "paypal": {"paypal.com"},
    "binance": {"binance.com"},
    "indodax": {"indodax.com"},
    "ojk": {"ojk.go.id"},
    "pajak": {"pajak.go.id"},
    "kominfo": {"kominfo.go.id", "komdigi.go.id"},
    "google": {"google.com", "google.co.id"},
    "apple": {"apple.com"},
    "microsoft": {"microsoft.com"},
}

LURE_KEYWORDS = {
    "hadiah", "undian", "login", "verify", "verifikasi", "claim", "klaim",
    "suspend", "blokir", "rekening", "resmi", "promo", "giveaway",
    "update", "aktivasi", "secure", "account", "bantuan", "bansos", "kuota",
}


def _is_official_brand_domain(host: str, brand: str) -> bool:
    officials = PROTECTED_BRANDS.get(brand, set())
    return any(host == dom or host.endswith("." + dom) for dom in officials)


class UrlPhishingModule(BaseOSINTModule):
    """Offline anti-phishing heuristics + redirect unshortener + urlscan/Wayback/VirusTotal."""

    name = "url_phishing"
    display_name = "URL Phishing & Scam Detector"
    description = "Analisis heuristik link phishing, peniruan merek (BCA/BRI/DANA/dll), redirect shortener, urlscan.io, Wayback, dan VirusTotal."
    category = "anti_scam"
    supported_targets = {TargetType.URL, TargetType.DOMAIN}
    requires_api_key = False
    api_key_env = "VIRUSTOTAL_API_KEY"

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

        # 1. Offline heuristic checks
        self._run_heuristics(full_url, host, parsed, findings)

        # 2. Safe redirect chain inspection (if URL or shortener)
        if target_type == TargetType.URL or host in URL_SHORTENERS:
            final_url, chain = await self._trace_redirects(full_url, ctx)
            if len(chain) > 1:
                findings.append(
                    Finding(
                        source=self.name,
                        category="redirect_chain",
                        title=f"Rantai Redirect Terdeteksi ({len(chain) - 1} hop)",
                        value=" -> ".join(chain),
                        url=final_url,
                        severity=Severity.MEDIUM if host in URL_SHORTENERS else Severity.INFO,
                        confidence=0.92,
                        risk_delta=10 if host in URL_SHORTENERS else 0,
                        metadata={"chain": chain, "final_url": final_url},
                    )
                )
                final_host = (urlparse(final_url).hostname or "").lower()
                if final_host and final_host != host:
                    did = make_entity_id("domain", final_host)
                    entities.append(EntityNode(id=did, label=final_host, entity_type="domain"))
                    edges.append(EntityEdge(source=root_id, target=did, relation="redirects_to"))
                    pivots.append({"value": final_host, "type": "domain", "reason": "Domain tujuan akhir redirect"})
                    self._run_heuristics(final_url, final_host, urlparse(final_url), findings, prefix="Landing URL: ")

        # 3. Public threat feeds (urlscan, Wayback, optional VirusTotal)
        await asyncio.gather(
            self._check_urlscan(host, ctx, findings),
            self._check_wayback(full_url, host, ctx, findings),
            self._check_virustotal(target, target_type, host, ctx, findings),
            return_exceptions=True,
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
            summary=f"Analisis anti-phishing untuk {host} selesai ({len(findings)} temuan).",
            pivot_candidates=pivots,
        )

    def _run_heuristics(
        self,
        full_url: str,
        host: str,
        parsed: Any,
        findings: list[Finding],
        prefix: str = "",
    ) -> None:
        if not host:
            return

        # Allowlist verified official banks, e-wallets, government, and global major platforms
        if is_trusted_domain(host):
            findings.append(
                Finding(
                    source=self.name,
                    category="trusted_domain",
                    title=f"{prefix}Domain Resmi / Terverifikasi",
                    value=f"Hostname '{host}' terdaftar dalam daftar domain resmi tepercaya.",
                    severity=Severity.INFO,
                    confidence=0.98,
                    risk_delta=0,
                    verification_status="verified",
                    signal_tier="trust",
                )
            )
            return

        labels = [p for p in host.split(".") if p]
        tld = labels[-1] if labels else ""
        has_suspicious_factor = False

        # IP address used as host
        try:
            ipaddress.ip_address(host)
            has_suspicious_factor = True
            findings.append(
                Finding(
                    source=self.name,
                    category="phishing_heuristic",
                    title=f"{prefix}URL Menggunakan IP Langsung",
                    value=f"Host berupa alamat IP ({host}) alih-alih nama domain resmi.",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    risk_delta=25,
                    signal_tier="suspicious",
                )
            )
        except ValueError:
            pass

        # Punycode / IDN Homograph
        if "xn--" in host:
            has_suspicious_factor = True
            findings.append(
                Finding(
                    source=self.name,
                    category="phishing_heuristic",
                    title=f"{prefix}Domain Punycode / Potensi Homograph",
                    value=f"Domain {host} mengandung punycode (xn--) yang sering dipakai meniru huruf mirip.",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    risk_delta=25,
                    signal_tier="suspicious",
                )
            )

        # @ credential trick
        if "@" in (parsed.netloc or ""):
            has_suspicious_factor = True
            findings.append(
                Finding(
                    source=self.name,
                    category="phishing_heuristic",
                    title=f"{prefix}Teknik Obfuskasi '@' pada URL",
                    value="URL mengandung karakter '@' untuk mengecoh pembaca tentang domain tujuan asli.",
                    severity=Severity.CRITICAL,
                    confidence=0.98,
                    risk_delta=35,
                    signal_tier="confirmed_threat",
                )
            )

        # Suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            has_suspicious_factor = True
            findings.append(
                Finding(
                    source=self.name,
                    category="phishing_heuristic",
                    title=f"{prefix}TLD Berisiko Tinggi (.{tld})",
                    value=f"Ekstensi domain .{tld} sangat sering dipakai untuk kampanye scam/phishing berbiaya murah.",
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    risk_delta=18,
                    signal_tier="suspicious",
                )
            )

        # Excessive subdomains above apex domain (ignoring single www.)
        depth = subdomain_depth(host)
        if depth >= 2:
            has_suspicious_factor = True
            findings.append(
                Finding(
                    source=self.name,
                    category="phishing_heuristic",
                    title=f"{prefix}Subdomain Berlapis ({depth} level di atas domain utama)",
                    value=f"Hostname {host} memiliki banyak level subdomain.",
                    severity=Severity.LOW,
                    confidence=0.75,
                    risk_delta=10,
                    signal_tier="advisory",
                )
            )

        # Shortener link
        if host in URL_SHORTENERS:
            has_suspicious_factor = True
            findings.append(
                Finding(
                    source=self.name,
                    category="phishing_heuristic",
                    title=f"{prefix}URL Shortener ({host})",
                    value="Tautan pemendek menyembunyikan domain asli tujuan.",
                    severity=Severity.LOW,
                    confidence=0.9,
                    risk_delta=10,
                    signal_tier="advisory",
                )
            )

        # Precision Brand Impersonation + Typosquatting Check
        url_lower = full_url.lower()
        apex = extract_registrable_domain(host)
        non_tld_part = host[: -(len(tld) + 1)] if tld and host.endswith("." + tld) else host
        raw_tokens = [t for t in re.split(r"[.\-_]+", non_tld_part) if t and t not in {"www", "co", "id", "com", "net", "org", "my", "web"}]

        impersonated_brands: list[str] = []
        brand_compound_lures = LURE_KEYWORDS | {"kaget", "official", "cs", "admin", "support", "brimo", "mybca", "livin"}
        short_brand_typos = {
            "bca": {"bcaa", "bbca", "bc4"},
            "bri": {"brii", "bbri", "br1"},
            "bni": {"bnii", "bbni", "bn1"},
            "bsi": {"bsii", "bbsi", "bs1"},
            "ovo": {"ovoo", "0v0", "0vo", "ov0"},
            "ojk": {"ojkk", "0jk"},
        }

        for brand in PROTECTED_BRANDS:
            if _is_official_brand_domain(host, brand):
                continue
            matched_brand = False
            for tok in raw_tokens:
                if tok in BRAND_FALSE_POSITIVE_WORDS:
                    continue
                tok_leet = normalize_leet(tok)
                if tok == brand or tok_leet == brand:
                    matched_brand = True
                    break
                if brand in short_brand_typos and (tok in short_brand_typos[brand] or tok_leet in short_brand_typos[brand]):
                    matched_brand = True
                    break
                if len(brand) >= 4:
                    if brand in tok_leet and any(lk in tok_leet for lk in brand_compound_lures):
                        matched_brand = True
                        break
                    if len(tok_leet) >= 4 and tok_leet not in BRAND_FALSE_POSITIVE_WORDS and levenshtein_distance(tok_leet, brand) == 1:
                        matched_brand = True
                        break
            if matched_brand:
                impersonated_brands.append(brand.upper())

        matched_lures = [kw for kw in sorted(LURE_KEYWORDS) if kw in url_lower]

        if impersonated_brands:
            has_suspicious_factor = True
            findings.append(
                Finding(
                    source=self.name,
                    category="brand_impersonation",
                    title=f"{prefix}Indikasi Peniruan Merek ({', '.join(impersonated_brands)})",
                    value=f"Domain '{host}' (apex: {apex}) meniru merek {', '.join(impersonated_brands)} tetapi BUKAN domain resmi!",
                    severity=Severity.CRITICAL if (matched_lures or tld in SUSPICIOUS_TLDS) else Severity.HIGH,
                    confidence=0.94,
                    risk_delta=35 if (matched_lures or tld in SUSPICIOUS_TLDS) else 25,
                    signal_tier="confirmed_threat",
                    metadata={"brands": impersonated_brands, "lure_keywords": matched_lures},
                )
            )

        # Unencrypted HTTP with login/verify lure
        is_http_sensitive = parsed.scheme == "http" and any(
            k in url_lower for k in ("login", "verify", "verifikasi", "claim", "klaim", "password", "otp", "pin")
        )
        if is_http_sensitive:
            has_suspicious_factor = True
            findings.append(
                Finding(
                    source=self.name,
                    category="phishing_heuristic",
                    title=f"{prefix}Halaman Sensitif Tanpa HTTPS",
                    value="Menggunakan HTTP tidak terenkripsi pada URL bertema login/verifikasi.",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    risk_delta=15,
                    signal_tier="suspicious",
                )
            )

        # Lure keywords only trigger risk when paired with another suspicious signal or >= 2 lures
        if matched_lures and not impersonated_brands and (has_suspicious_factor or len(matched_lures) >= 2):
            findings.append(
                Finding(
                    source=self.name,
                    category="phishing_heuristic",
                    title=f"{prefix}Kata Kunci Pancingan Phishing/Scam",
                    value=f"Terdeteksi kata umpan: {', '.join(matched_lures[:6])}",
                    severity=Severity.MEDIUM if has_suspicious_factor else Severity.LOW,
                    confidence=0.82,
                    risk_delta=12 if has_suspicious_factor else 6,
                    signal_tier="suspicious" if has_suspicious_factor else "advisory",
                )
            )

    async def _trace_redirects(self, start_url: str, ctx: InvestigationContext) -> tuple[str, list[str]]:
        chain = [start_url]
        current = start_url
        for _ in range(6):
            try:
                async with ctx.http_session.get(current, allow_redirects=False, timeout=6) as resp:
                    if resp.status in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("Location")
                        if not loc:
                            break
                        nxt = urljoin(current, loc)
                        if nxt in chain:
                            break
                        chain.append(nxt)
                        current = nxt
                    else:
                        break
            except Exception:
                break
        return current, chain

    async def _check_urlscan(self, host: str, ctx: InvestigationContext, findings: list[Finding]) -> None:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{quote(host)}&size=5"
        headers: dict[str, str] = {}
        key = ctx.config.get_api_key("URLSCAN_API_KEY")
        if key:
            headers["API-Key"] = key
        try:
            async with ctx.http_session.get(url, headers=headers, timeout=8) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
        except Exception:
            return
        results = data.get("results") or []
        if not results:
            return
        malicious_count = sum(
            1 for r in results if ((r.get("verdicts") or {}).get("overall") or {}).get("malicious")
        )
        sample_link = (results[0].get("result") or f"https://urlscan.io/search/#domain:{host}")
        findings.append(
            Finding(
                source=self.name,
                category="threat_feed",
                title="Riwayat Pemindaian urlscan.io",
                value=f"{len(results)} snapshot ditemukan (Malicious verdicts: {malicious_count})",
                url=str(sample_link),
                severity=Severity.HIGH if malicious_count > 0 else Severity.INFO,
                confidence=0.88,
                risk_delta=35 if malicious_count > 0 else 0,
                signal_tier="confirmed_threat" if malicious_count > 0 else "info",
            )
        )

    async def _check_wayback(
        self, full_url: str, host: str, ctx: InvestigationContext, findings: list[Finding]
    ) -> None:
        api = f"https://archive.org/wayback/available?url={quote(host)}"
        try:
            async with ctx.http_session.get(api, timeout=7) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
        except Exception:
            return
        closest = ((data.get("archived_snapshots") or {}).get("closest") or {})
        if closest.get("available"):
            ts = str(closest.get("timestamp") or "")
            findings.append(
                Finding(
                    source=self.name,
                    category="archive",
                    title="Arsip Wayback Machine Tersedia",
                    value=f"Snapshot tercatat: {ts[:8] or '-'}",
                    url=str(closest.get("url") or f"https://web.archive.org/web/*/{host}"),
                    severity=Severity.INFO,
                    confidence=0.9,
                    signal_tier="trust",
                )
            )
        else:
            findings.append(
                Finding(
                    source=self.name,
                    category="archive",
                    title="Belum Ada Arsip Wayback Machine",
                    value=f"Domain {host} belum pernah terarsip di archive.org (umum pada situs baru).",
                    url=f"https://web.archive.org/web/*/{full_url}",
                    severity=Severity.INFO,
                    confidence=0.75,
                )
            )

    async def _check_virustotal(
        self,
        target: str,
        target_type: TargetType,
        host: str,
        ctx: InvestigationContext,
        findings: list[Finding],
    ) -> None:
        vt_key = ctx.config.get_api_key("VIRUSTOTAL_API_KEY")
        if not vt_key:
            return
        headers = {"x-apikey": vt_key}
        if target_type == TargetType.URL:
            url_id = base64.urlsafe_b64encode(target.encode("utf-8")).decode("ascii").rstrip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            vt_gui = f"https://www.virustotal.com/gui/url/{url_id}"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{quote(host)}"
            vt_gui = f"https://www.virustotal.com/gui/domain/{host}"
        try:
            async with ctx.http_session.get(endpoint, headers=headers, timeout=10) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
        except Exception:
            return
        stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
        mal = int(stats.get("malicious", 0))
        susp = int(stats.get("suspicious", 0))
        harm = int(stats.get("harmless", 0))
        sev = Severity.INFO
        delta = 0
        if mal >= 3:
            sev = Severity.CRITICAL
            delta = 40
        elif mal >= 1 or susp >= 2:
            sev = Severity.HIGH
            delta = 25
        findings.append(
            Finding(
                source=self.name,
                category="threat_feed",
                title="Hasil VirusTotal v3",
                value=f"Malicious: {mal} | Suspicious: {susp} | Harmless: {harm}",
                url=vt_gui,
                severity=sev,
                confidence=0.96,
                risk_delta=delta,
                signal_tier="confirmed_threat" if delta > 0 else "info",
                metadata=stats,
            )
        )


class ScamDorkModule(BaseOSINTModule):
    """Generates curated anti-scam Google dorks and Indonesian fraud verification links."""

    name = "scam_dorks"
    display_name = "Anti-Scam Dorks & Portal Cek Penipu"
    description = "Membuat tautan investigasi cepat ke laporan penipuan (CekRekening, Kredibel, ScamAdviser, Google Dorks, Sosmed)."
    category = "anti_scam"
    supported_targets = {
        TargetType.USERNAME,
        TargetType.EMAIL,
        TargetType.PHONE,
        TargetType.DOMAIN,
        TargetType.FULL_NAME,
        TargetType.CRYPTO_WALLET,
    }

    async def run(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
    ) -> ModuleResult:
        started = time.perf_counter()
        q_exact = quote(f'"{target}"')
        q_scam = quote(f'"{target}" (penipu OR penipuan OR scam OR fraud OR modus OR lapor)')
        q_kredibel = quote(f'"{target}" site:kredibel.co.id OR site:cekrekening.id')
        q_social = quote(
            f'"{target}" (site:facebook.com OR site:instagram.com OR site:tiktok.com OR site:x.com OR site:reddit.com)'
        )

        dorks = [
            ("Google Scam & Laporan Penipuan", f"https://www.google.com/search?q={q_scam}", "Cari laporan korban di Google"),
            ("Google Exact Match", f"https://www.google.com/search?q={q_exact}", "Pencarian persis lintas web"),
            ("Dork Kredibel & CekRekening", f"https://www.google.com/search?q={q_kredibel}", "Cari di portal pelaporan penipu Indonesia"),
            ("Portal CekRekening Komdigi", "https://cekrekening.id/home", "Cek rekening/nomor terindikasi penipuan"),
            ("Portal Kredibel.co.id", f"https://www.kredibel.co.id/search?q={quote(target)}", "Cek riwayat laporan penipuan Kredibel"),
            ("Cross-Social Dork", f"https://www.google.com/search?q={q_social}", "Cari sebutan di FB/IG/TikTok/X/Reddit"),
        ]
        if target_type == TargetType.DOMAIN:
            dorks.append(
                ("ScamAdviser Trust Check", f"https://www.scamadviser.com/check-website/{quote(target)}", "Skor kepercayaan domain")
            )

        findings = [
            Finding(
                source=self.name,
                category="investigation_link",
                title=title,
                value=desc,
                url=url,
                severity=Severity.INFO,
                confidence=1.0,
            )
            for title, url, desc in dorks
        ]
        elapsed = int((time.perf_counter() - started) * 1000)
        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            status="ok",
            duration_ms=elapsed,
            findings=findings,
            summary=f"Dibuat {len(findings)} tautan verifikasi anti-penipuan.",
        )
