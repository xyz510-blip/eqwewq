"""Free public threat intelligence feeds: StopForumSpam, URLhaus (abuse.ch), and ThreatFox (abuse.ch)."""

from __future__ import annotations

import asyncio
import time
from urllib.parse import quote, urlparse

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.models import Finding, ModuleResult, Severity, TargetType


class ThreatFeedsModule(BaseOSINTModule):
    """Cross-checks IPs, domains, URLs, emails, and usernames against public anti-abuse feeds."""

    name = "threat_feeds"
    display_name = "Public Threat Feeds (URLhaus / ThreatFox / StopForumSpam)"
    description = "Memeriksa IOC ke database ancaman publik gratis: abuse.ch URLhaus, ThreatFox, dan StopForumSpam."
    category = "anti_scam"
    supported_targets = {
        TargetType.IP,
        TargetType.DOMAIN,
        TargetType.URL,
        TargetType.EMAIL,
        TargetType.USERNAME,
    }

    async def run(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
    ) -> ModuleResult:
        started = time.perf_counter()
        findings: list[Finding] = []

        tasks = []
        if target_type in {TargetType.IP, TargetType.EMAIL, TargetType.USERNAME}:
            tasks.append(self._check_stopforumspam(target, target_type, ctx, findings))
        if target_type in {TargetType.IP, TargetType.DOMAIN, TargetType.URL}:
            tasks.append(self._check_urlhaus(target, target_type, ctx, findings))
            tasks.append(self._check_threatfox(target, target_type, ctx, findings))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        elapsed = int((time.perf_counter() - started) * 1000)
        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            status="ok",
            duration_ms=elapsed,
            findings=findings,
            summary=f"Pengecekan public threat feeds selesai ({len(findings)} temuan).",
        )

    async def _check_stopforumspam(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
        findings: list[Finding],
    ) -> None:
        param_map = {
            TargetType.IP: "ip",
            TargetType.EMAIL: "email",
            TargetType.USERNAME: "username",
        }
        field_name = param_map.get(target_type)
        if not field_name:
            return
        url = f"https://api.stopforumspam.org/api?{field_name}={quote(target)}&json"
        try:
            async with ctx.http_session.get(url, timeout=6) as resp:
                if resp.status != 200:
                    return
                data = await resp.json(content_type=None)
        except Exception:
            return

        if not isinstance(data, dict) or not data.get("success"):
            return
        entry = data.get(field_name) or {}
        appears = int(entry.get("appears", 0) or 0)
        frequency = int(entry.get("frequency", 0) or 0)
        confidence = float(entry.get("confidence", 0.0) or 0.0)

        # Strict threshold to prevent common-username false positives
        if appears == 1 and (confidence >= 50.0 or frequency >= 2):
            findings.append(
                Finding(
                    source=self.name,
                    category="threat_feed",
                    title="Tercatat di StopForumSpam Database",
                    value=f"Dilaporkan {frequency} kali (Confidence: {confidence:.1f}% | Last seen: {entry.get('lastseen', '-')}).",
                    url=f"https://www.stopforumspam.com/search?q={quote(target)}",
                    severity=Severity.HIGH,
                    confidence=min(0.98, max(0.75, confidence / 100.0)),
                    risk_delta=30,
                    verification_status="verified",
                    signal_tier="confirmed_threat",
                    metadata=entry,
                )
            )

    async def _check_urlhaus(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
        findings: list[Finding],
    ) -> None:
        host = (urlparse(target).hostname or target) if target_type == TargetType.URL else target
        if target_type == TargetType.URL:
            endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
            payload = {"url": target}
        else:
            endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
            payload = {"host": host}

        try:
            async with ctx.http_session.post(endpoint, data=payload, timeout=6) as resp:
                if resp.status != 200:
                    return
                data = await resp.json(content_type=None)
        except Exception:
            return

        if not isinstance(data, dict):
            return
        q_status = str(data.get("query_status") or "").lower()
        if q_status == "ok":
            threat = str(data.get("threat") or "malware_download")
            url_count = data.get("url_count") or len(data.get("urls") or []) or 1
            ref_link = str(data.get("urlhaus_reference") or f"https://urlhaus.abuse.ch/browse.php?search={quote(host)}")
            findings.append(
                Finding(
                    source=self.name,
                    category="threat_feed",
                    title="Tercatat di abuse.ch URLhaus (Malware / Phishing Host)",
                    value=f"Status: ACTIVE/KNOWN | Threat: {threat} | Jumlah IOC URL: {url_count}",
                    url=ref_link,
                    severity=Severity.CRITICAL,
                    confidence=0.98,
                    risk_delta=35,
                    verification_status="verified",
                    signal_tier="confirmed_threat",
                )
            )

    async def _check_threatfox(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
        findings: list[Finding],
    ) -> None:
        search_val = (urlparse(target).hostname or target) if target_type == TargetType.URL else target
        try:
            async with ctx.http_session.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": search_val},
                timeout=6,
            ) as resp:
                if resp.status != 200:
                    return
                data = await resp.json(content_type=None)
        except Exception:
            return

        if not isinstance(data, dict) or str(data.get("query_status") or "").lower() != "ok":
            return
        items = data.get("data") or []
        if isinstance(items, list) and items:
            first = items[0]
            malware = str(first.get("malware_printable") or first.get("malware") or "Unknown Threat")
            threat_type = str(first.get("threat_type") or "-")
            findings.append(
                Finding(
                    source=self.name,
                    category="threat_feed",
                    title="Tercatat di abuse.ch ThreatFox IOC",
                    value=f"{len(items)} IOC cocok | Malware/Campaign: {malware} | Tipe: {threat_type}",
                    url="https://threatfox.abuse.ch/browse/",
                    severity=Severity.CRITICAL,
                    confidence=0.97,
                    risk_delta=35,
                    verification_status="verified",
                    signal_tier="confirmed_threat",
                )
            )
