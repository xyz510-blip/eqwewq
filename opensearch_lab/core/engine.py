"""Async OSINT investigation orchestration engine with auto-pivoting."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Iterable
from urllib.parse import urlparse

import aiohttp

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.config import AppConfig
from opensearch_lab.core.correlator import Correlator
from opensearch_lab.core.detector import detect_target_type
from opensearch_lab.core.known_entities import GENERIC_EMAIL_LOCAL_PARTS
from opensearch_lab.core.models import (
    Finding,
    InvestigationReport,
    ModuleResult,
    TargetType,
    utc_now_iso,
)
from opensearch_lab.core.registry import ModuleRegistry
from opensearch_lab.core.risk_scorer import RiskScorer
from opensearch_lab.core.storage import Storage
from opensearch_lab.core.verifier import ResultVerifier

FREE_WEBMAIL_DOMAINS: set[str] = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.co.id",
    "ymail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "aol.com",
    "zoho.com",
    "mail.com",
    "gmx.com",
}


class InvestigationEngine:
    """Runs selected OSINT modules, executes auto-pivots, scores risk, and saves dossiers."""

    def __init__(
        self,
        config: AppConfig,
        registry: ModuleRegistry,
        storage: Storage,
    ) -> None:
        self.config = config
        self.registry = registry
        self.storage = storage

    async def investigate(
        self,
        raw_query: str,
        target_hint: str | None = None,
        include_modules: Iterable[str] | None = None,
        exclude_modules: Iterable[str] | None = None,
        include_slow: bool = True,
        auto_pivot: bool | None = None,
        maigret_top_sites: int | None = None,
        verify_profiles: bool = True,
        notes: str = "",
    ) -> InvestigationReport:
        """Run a full investigation asynchronously and persist the dossier."""
        start_perf = time.perf_counter()
        target_type, target = detect_target_type(raw_query, hint=target_hint)
        case_id = f"CASE-{uuid.uuid4().hex[:10].upper()}"
        created_at = utc_now_iso()

        if auto_pivot is None:
            auto_pivot = self.config.enable_auto_pivot

        options: dict[str, Any] = {
            "maigret_top_sites": maigret_top_sites or self.config.maigret_top_sites,
            "include_slow": include_slow,
        }

        timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)
        headers = {"User-Agent": self.config.user_agent}

        module_results: list[ModuleResult] = []
        executed_keys: set[tuple[str, str]] = set()
        filtered_fps: list[Finding] = []

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            ctx = InvestigationContext(
                config=self.config,
                http_session=session,
                storage=self.storage,
                options=options,
            )

            primary_modules = self.registry.select_for_target(
                target_type=target_type,
                config=self.config,
                include_modules=include_modules,
                exclude_modules=exclude_modules,
                include_slow=include_slow,
            )

            primary_results = await self._run_module_batch(
                primary_modules, target, target_type, ctx, executed_keys
            )
            module_results.extend(primary_results)

            # Auto-pivot stage (depth 1) for connected infrastructure / aliases
            if auto_pivot and self.config.max_pivot_depth >= 1:
                pivot_jobs = self._derive_auto_pivots(
                    target=target,
                    target_type=target_type,
                    primary_results=primary_results,
                    include_modules=include_modules,
                    exclude_modules=exclude_modules,
                    include_slow=include_slow,
                )
                if pivot_jobs:
                    pivot_coros = [
                        self._run_single_module(mod, p_target, p_type, ctx, executed_keys)
                        for mod, p_target, p_type in pivot_jobs
                    ]
                    pivot_raw = await asyncio.gather(*pivot_coros)
                    module_results.extend([r for r in pivot_raw if r is not None])

            # Correlate entities & findings
            findings, entities, edges, pivot_suggestions = Correlator.correlate(
                root_target=target,
                root_type=target_type,
                module_results=module_results,
            )

            # Verify live social profiles & filter soft-404 false positives
            if verify_profiles:
                findings, filtered_fps = await ResultVerifier.verify_profile_urls(findings, session)

        # Match against watchlist and prior cases
        indicators = [target, raw_query]
        for ent in entities:
            if ent.entity_type in {
                "username",
                "email",
                "phone",
                "domain",
                "ip",
                "crypto_wallet",
                "bank_account",
                "image_dhash",
            }:
                indicators.append(ent.label)
        watchlist_matches = self.storage.match_watchlist(indicators, exclude_case_id=case_id)

        # Risk assessment
        risk = RiskScorer.evaluate(findings=findings, watchlist_matches=watchlist_matches)

        duration_ms = int((time.perf_counter() - start_perf) * 1000)
        report = InvestigationReport(
            case_id=case_id,
            query=target,
            target_type=target_type,
            created_at=created_at,
            duration_ms=duration_ms,
            modules_run=module_results,
            findings=findings,
            entities=entities,
            edges=edges,
            risk=risk,
            pivot_suggestions=pivot_suggestions,
            watchlist_matches=watchlist_matches,
            notes=notes,
            metadata={
                "raw_query": raw_query,
                "include_slow": include_slow,
                "auto_pivot": auto_pivot,
                "verify_profiles": verify_profiles,
            },
            filtered_false_positives=filtered_fps,
        )
        self.storage.save_case(report)
        return report

    def investigate_sync(self, *args: Any, **kwargs: Any) -> InvestigationReport:
        """Synchronous convenience wrapper for CLI and Flask endpoints."""
        return asyncio.run(self.investigate(*args, **kwargs))

    async def _run_module_batch(
        self,
        modules: list[BaseOSINTModule],
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
        executed_keys: set[tuple[str, str]],
    ) -> list[ModuleResult]:
        sem = asyncio.Semaphore(max(1, self.config.max_concurrent_modules))

        async def _guarded(mod: BaseOSINTModule) -> ModuleResult | None:
            async with sem:
                return await self._run_single_module(mod, target, target_type, ctx, executed_keys)

        results = await asyncio.gather(*[_guarded(m) for m in modules])
        return [r for r in results if r is not None]

    async def _run_single_module(
        self,
        mod: BaseOSINTModule,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
        executed_keys: set[tuple[str, str]],
    ) -> ModuleResult | None:
        key = (mod.name, target.strip().lower())
        if key in executed_keys:
            return None
        executed_keys.add(key)

        started = time.perf_counter()
        try:
            res = await asyncio.wait_for(
                mod.run(target, target_type, ctx),
                timeout=float(self.config.module_timeout),
            )
            return res
        except asyncio.TimeoutError:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ModuleResult(
                module_name=mod.name,
                display_name=mod.display_name,
                status="error",
                duration_ms=elapsed,
                error=f"Timeout after {self.config.module_timeout}s",
            )
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ModuleResult(
                module_name=mod.name,
                display_name=mod.display_name,
                status="error",
                duration_ms=elapsed,
                error=f"{type(exc).__name__}: {exc}",
            )

    def _derive_auto_pivots(
        self,
        target: str,
        target_type: TargetType,
        primary_results: list[ModuleResult],
        include_modules: Iterable[str] | None,
        exclude_modules: Iterable[str] | None,
        include_slow: bool,
    ) -> list[tuple[BaseOSINTModule, str, TargetType]]:
        jobs: list[tuple[BaseOSINTModule, str, TargetType]] = []

        def pick(names: list[str], p_type: TargetType) -> list[BaseOSINTModule]:
            available = self.registry.select_for_target(
                target_type=p_type,
                config=self.config,
                include_modules=include_modules,
                exclude_modules=exclude_modules,
                include_slow=include_slow,
            )
            return [m for m in available if m.name in names]

        # 1. URL -> pivot to hostname (domain or IP)
        if target_type == TargetType.URL:
            host = (urlparse(target).hostname or "").strip().lower()
            if host:
                detected_host_type, norm_host = detect_target_type(host)
                if detected_host_type == TargetType.DOMAIN:
                    for mod in pick(["rdap_whois", "shodan", "dns_ssl"], TargetType.DOMAIN):
                        jobs.append((mod, norm_host, TargetType.DOMAIN))
                elif detected_host_type == TargetType.IP:
                    for mod in pick(["shodan", "ip_reputation", "rdap_whois"], TargetType.IP):
                        jobs.append((mod, norm_host, TargetType.IP))

        # 2. DOMAIN -> pivot to first resolved IP from dns_ssl findings
        if target_type == TargetType.DOMAIN:
            for res in primary_results:
                if res.module_name == "dns_ssl":
                    for f in res.findings:
                        if f.category == "dns" and f.title == "DNS A Record":
                            first_ip = f.value.split(",")[0].strip()
                            if first_ip:
                                for mod in pick(["shodan", "ip_reputation"], TargetType.IP):
                                    jobs.append((mod, first_ip, TargetType.IP))
                                break

        # 3. EMAIL -> domain infra (skip free webmail for RDAP noise) + fast username lookup
        if target_type == TargetType.EMAIL and "@" in target:
            local_part, domain = target.split("@", 1)
            domain = domain.strip().lower()
            if domain and domain not in FREE_WEBMAIL_DOMAINS:
                for mod in pick(["rdap_whois", "url_phishing"], TargetType.DOMAIN):
                    jobs.append((mod, domain, TargetType.DOMAIN))
            if local_part and local_part.lower() not in GENERIC_EMAIL_LOCAL_PARTS:
                for mod in pick(["public_profiles"], TargetType.USERNAME):
                    jobs.append((mod, local_part, TargetType.USERNAME))

        return jobs
