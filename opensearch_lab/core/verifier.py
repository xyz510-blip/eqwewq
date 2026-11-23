"""Verification & false-positive elimination layer for OSINT findings and pivots."""

from __future__ import annotations

import asyncio
import html
import re
from typing import Any
from urllib.parse import urlparse

import aiohttp

from opensearch_lab.core.domain_utils import clean_host
from opensearch_lab.core.known_entities import (
    GENERIC_EMAIL_LOCAL_PARTS,
    LOGIN_WALL_SITES,
    SHARED_CDN_HOSTING_KEYWORDS,
)
from opensearch_lab.core.models import Finding

SOFT_404_PATTERNS: tuple[str, ...] = (
    "page not found",
    "user not found",
    "profile not found",
    "doesn't exist",
    "does not exist",
    "page isn't available",
    "page is not available",
    "this account has been suspended",
    "account suspended",
    "sorry, nobody on reddit",
    "404 error",
    "error 404",
    "not found",
    "buy this domain",
    "domain is for sale",
    "this domain is for sale",
    "nobody on reddit goes by that name",
    "sorry, that page doesn’t exist",
    "sorry, that page doesn't exist",
)

GENERIC_UI_NOISE: set[str] = {
    "log in",
    "login",
    "sign up",
    "signup",
    "sign in",
    "facebook",
    "twitter",
    "x",
    "instagram",
    "tiktok",
    "linkedin",
    "error",
    "404",
    "home",
    "not found",
    "page not found",
    "untitled",
    "just a moment...",
}

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
OG_TITLE_RE = re.compile(
    r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\'](.*?)["\']',
    re.IGNORECASE | re.DOTALL,
)


def normalize_profile_url(url: str) -> str:
    """Canonicalize social profile URLs so Maigret/Sherlock/PublicProfile deduplicate cleanly."""
    u = (url or "").strip()
    if not u:
        return ""
    parsed = urlparse(u)
    host = (parsed.netloc or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if host.startswith("m."):
        host = host[2:]
    if host.startswith("mobile."):
        host = host[7:]
    if host == "twitter.com":
        host = "x.com"
    path = (parsed.path or "").rstrip("/")
    return f"{host}{path}".lower()


def _site_name_from_finding(f: Finding) -> str:
    site = str((f.metadata or {}).get("site") or "").strip().lower()
    if site:
        return site
    host = (urlparse(f.url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host.split(".", 1)[0] if host else ""


def _is_login_wall_site(f: Finding) -> bool:
    site = _site_name_from_finding(f)
    if site in LOGIN_WALL_SITES:
        return True
    host = (urlparse(f.url).hostname or "").lower()
    return any(lw in host.split(".") for lw in LOGIN_WALL_SITES)


class ResultVerifier:
    """Deduplicates cross-tool findings, filters soft-404s, tags login walls, and scrubs noise pivots."""

    @classmethod
    def deduplicate_and_tag(
        cls,
        findings: list[Finding],
        pivots: list[dict[str, str]],
    ) -> tuple[list[Finding], list[dict[str, str]]]:
        """Merge identical social profiles across tools, tag login walls, and filter noisy pivots."""
        profile_groups: dict[str, list[Finding]] = {}
        non_profiles: list[Finding] = []

        for f in findings:
            if f.category == "social_profile" and f.url:
                norm_u = normalize_profile_url(f.url)
                if norm_u:
                    profile_groups.setdefault(norm_u, []).append(f)
                    continue
            non_profiles.append(f)

        merged_profiles: list[Finding] = []
        for norm_u, group in profile_groups.items():
            # Pick richest finding as primary (prefer public_profiles / maigret with ids)
            group.sort(
                key=lambda item: (
                    1 if item.source == "public_profiles" else 0,
                    len((item.metadata or {}).get("extracted_ids") or {}),
                    item.confidence,
                ),
                reverse=True,
            )
            primary = group[0]
            sources = sorted({g.source for g in group})

            if len(sources) >= 2:
                primary.verification_status = "corroborated"
                primary.confidence = max(primary.confidence, 0.95)
                primary.metadata["corroborated_by"] = sources
                if "terkonfirmasi silang" not in primary.title.lower():
                    primary.title = f"{primary.title} [Terkonfirmasi {len(sources)} Sumber]"
            elif primary.source == "public_profiles":
                primary.verification_status = "verified"

            if _is_login_wall_site(primary):
                has_extracted = bool((primary.metadata or {}).get("extracted_ids"))
                if not has_extracted:
                    primary.verification_status = "unverified_login_wall"
                    primary.confidence = min(primary.confidence, 0.45)
                    if "[Perlu cek manual" not in primary.value:
                        primary.value = f"{primary.value} [Perlu cek manual — situs login-wall]"

            merged_profiles.append(primary)

        # Scrub noisy pivots (generic UI words, generic email local-parts, shared hosting PTRs)
        clean_pivots: list[dict[str, str]] = []
        for p in pivots:
            val = str(p.get("value", "")).strip()
            ptype = str(p.get("type", "")).strip().lower()
            vlow = val.lower()
            if not val:
                continue
            if vlow in GENERIC_UI_NOISE or len(val) < 3:
                continue
            if ptype == "username" and vlow in GENERIC_EMAIL_LOCAL_PARTS:
                continue
            if ptype == "domain":
                ch = clean_host(val)
                if any(kw in ch for kw in SHARED_CDN_HOSTING_KEYWORDS) and "shodan" in str(p.get("reason", "")).lower():
                    continue
            clean_pivots.append(p)

        combined = non_profiles + merged_profiles
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        combined.sort(
            key=lambda f: (sev_rank.get(f.severity.value, 0), f.risk_delta, f.confidence),
            reverse=True,
        )
        return combined, clean_pivots

    @classmethod
    async def verify_profile_urls(
        cls,
        findings: list[Finding],
        session: aiohttp.ClientSession,
        max_checks: int = 12,
    ) -> tuple[list[Finding], list[Finding]]:
        """Perform lightweight async HTTP soft-404 verification on unverified social profile URLs."""
        candidates: list[Finding] = []
        keep: list[Finding] = []

        for f in findings:
            if (
                f.category == "social_profile"
                and f.url.startswith(("http://", "https://"))
                and f.verification_status in {"unverified", "corroborated"}
                and not _is_login_wall_site(f)
                and f.source != "public_profiles"
                and len(candidates) < max_checks
            ):
                candidates.append(f)
            else:
                keep.append(f)

        if not candidates:
            return findings, []

        sem = asyncio.Semaphore(6)
        filtered_fps: list[Finding] = []

        async def _check_one(finding: Finding) -> tuple[Finding, bool]:
            async with sem:
                try:
                    async with session.get(finding.url, timeout=5, allow_redirects=True) as resp:
                        if resp.status in (404, 410, 451):
                            finding.verification_status = "filtered_false_positive"
                            finding.metadata["filter_reason"] = f"HTTP {resp.status}"
                            return finding, False
                        ctype = (resp.headers.get("Content-Type") or "").lower()
                        if "text/html" in ctype or "application/xhtml" in ctype or not ctype:
                            raw = await resp.content.read(32768)
                            text = raw.decode("utf-8", errors="ignore")
                            low = text.lower()
                            t_match = TITLE_RE.search(text)
                            og_match = OG_TITLE_RE.search(text)
                            page_title = html.unescape((og_match.group(1) if og_match else (t_match.group(1) if t_match else ""))).strip()
                            title_low = page_title.lower()

                            for pat in SOFT_404_PATTERNS:
                                if pat in title_low or (pat in low and len(low) < 12000):
                                    finding.verification_status = "filtered_false_positive"
                                    finding.metadata["filter_reason"] = f"Soft-404 matched: '{pat}'"
                                    return finding, False

                            if resp.status == 200:
                                finding.verification_status = (
                                    "corroborated" if finding.verification_status == "corroborated" else "verified"
                                )
                                finding.confidence = max(finding.confidence, 0.94)
                                if page_title and page_title.lower() not in GENERIC_UI_NOISE:
                                    finding.metadata["page_title"] = page_title[:120]
                except Exception:
                    # Network timeout/block does not mark a finding as false positive; keep as unverified
                    return finding, True
            return finding, True

        checked = await asyncio.gather(*[_check_one(c) for c in candidates])
        for f, is_valid in checked:
            if is_valid:
                keep.append(f)
            else:
                filtered_fps.append(f)

        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        keep.sort(
            key=lambda f: (sev_rank.get(f.severity.value, 0), f.risk_delta, f.confidence),
            reverse=True,
        )
        return keep, filtered_fps
