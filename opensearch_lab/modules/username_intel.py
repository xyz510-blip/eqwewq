"""Username & profile OSINT modules: Maigret, Sherlock, and fast direct profile lookups."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.correlator import make_entity_id
from opensearch_lab.core.known_entities import LOGIN_WALL_SITES
from opensearch_lab.core.models import (
    EntityEdge,
    EntityNode,
    Finding,
    ModuleResult,
    Severity,
    TargetType,
)
from opensearch_lab.core.verifier import GENERIC_UI_NOISE


def _utf8_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


class MaigretModule(BaseOSINTModule):
    """Deep username hunt and socid-extractor metadata parsing via Maigret."""

    name = "maigret"
    display_name = "Maigret Username Hunter"
    description = "Mencari username di ratusan platform sosial & mengekstrak metadata profil (socid-extractor)."
    category = "username_osint"
    supported_targets = {TargetType.USERNAME}
    is_slow = True

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
        top_sites = int(ctx.options.get("maigret_top_sites") or ctx.config.maigret_top_sites)
        req_timeout = int(ctx.config.maigret_timeout)

        with tempfile.TemporaryDirectory(prefix="maigret_") as tmpdir:
            cmd = [
                sys.executable,
                "-m",
                "maigret",
                target,
                "--top-sites",
                str(top_sites),
                "--timeout",
                str(req_timeout),
                "-J",
                "simple",
                "--folderoutput",
                tmpdir,
                "--no-color",
                "--no-progressbar",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_utf8_env(),
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=max(30, ctx.config.module_timeout - 5),
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                elapsed = int((time.perf_counter() - started) * 1000)
                return ModuleResult(
                    module_name=self.name,
                    display_name=self.display_name,
                    status="error",
                    duration_ms=elapsed,
                    error="Maigret subprocess timed out",
                )

            json_files = list(Path(tmpdir).glob("*.json"))
            parsed_data: dict[str, Any] = {}
            if json_files:
                try:
                    raw_text = json_files[0].read_text(encoding="utf-8", errors="ignore")
                    loaded = json.loads(raw_text)
                    if isinstance(loaded, dict):
                        parsed_data = loaded
                except Exception:
                    parsed_data = {}

            for site_name, entry in parsed_data.items():
                if not isinstance(entry, dict):
                    continue
                url_user = str(entry.get("url_user") or "").strip()
                status_obj = entry.get("status") if isinstance(entry.get("status"), dict) else {}
                status_str = str(status_obj.get("status") or entry.get("status") or "").lower()
                if not url_user:
                    continue
                if status_str and "claim" not in status_str and "found" not in status_str:
                    continue

                tags = status_obj.get("tags") or entry.get("tags") or []
                ids_meta = status_obj.get("ids") or entry.get("ids") or {}
                if not isinstance(ids_meta, dict):
                    ids_meta = {}

                is_lw = site_name.strip().lower() in LOGIN_WALL_SITES and not ids_meta
                findings.append(
                    Finding(
                        source=self.name,
                        category="social_profile",
                        title=f"Profil ditemukan di {site_name}",
                        value=f"{url_user}{' [Perlu cek manual — situs login-wall]' if is_lw else ''}",
                        url=url_user,
                        severity=Severity.INFO,
                        confidence=0.45 if is_lw else 0.88,
                        verification_status="unverified_login_wall" if is_lw else "unverified",
                        metadata={"site": site_name, "tags": tags, "extracted_ids": ids_meta},
                    )
                )

                prof_id = make_entity_id("profile", f"{site_name}:{target}")
                entities.append(
                    EntityNode(
                        id=prof_id,
                        label=f"{site_name} ({target})",
                        entity_type="profile",
                        metadata={"url": url_user, "site": site_name},
                    )
                )
                edges.append(EntityEdge(source=root_id, target=prof_id, relation="has_account"))

                # Extract rich pivots discovered by Maigret's socid-extractor
                for k, v in ids_meta.items():
                    if not v:
                        continue
                    v_str = str(v).strip()
                    if v_str.lower() in GENERIC_UI_NOISE:
                        continue
                    k_low = str(k).lower()
                    if "email" in k_low and "@" in v_str:
                        pivots.append({"value": v_str, "type": "email", "reason": f"Email diekstrak dari {site_name}"})
                        e_id = make_entity_id("email", v_str)
                        entities.append(EntityNode(id=e_id, label=v_str, entity_type="email"))
                        edges.append(EntityEdge(source=prof_id, target=e_id, relation="exposes_email"))
                    elif any(name_k in k_low for name_k in ("fullname", "name", "username")) and len(v_str) >= 3:
                        p_type = "full_name" if " " in v_str else "username"
                        pivots.append({"value": v_str, "type": p_type, "reason": f"Alias/Nama di {site_name}"})

            # Fallback regex parse from stdout if JSON didn't materialize
            if not findings:
                stdout_txt = stdout_b.decode("utf-8", errors="ignore")
                for match in re.finditer(r"\[\+\]\s+([^:]+):\s+(https?://\S+)", stdout_txt):
                    site, link = match.group(1).strip(), match.group(2).strip()
                    findings.append(
                        Finding(
                            source=self.name,
                            category="social_profile",
                            title=f"Profil ditemukan di {site}",
                            value=link,
                            url=link,
                            severity=Severity.INFO,
                            confidence=0.85,
                            metadata={"site": site},
                        )
                    )
                    prof_id = make_entity_id("profile", f"{site}:{target}")
                    entities.append(EntityNode(id=prof_id, label=f"{site} ({target})", entity_type="profile"))
                    edges.append(EntityEdge(source=root_id, target=prof_id, relation="has_account"))

            err_txt = stderr_b.decode("utf-8", errors="ignore").strip()
            elapsed = int((time.perf_counter() - started) * 1000)
            status = "ok" if (proc.returncode == 0 or findings) else "partial"
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                status=status,
                duration_ms=elapsed,
                findings=findings,
                entities=entities,
                edges=edges,
                summary=f"Maigret (top {top_sites} sites) menemukan {len(findings)} profil.",
                error="" if findings or proc.returncode == 0 else err_txt[:300],
                pivot_candidates=pivots,
            )


class SherlockModule(BaseOSINTModule):
    """Cross-platform username discovery via Sherlock Project."""

    name = "sherlock"
    display_name = "Sherlock Username Search"
    description = "Mencari jejak akun username di ratusan situs menggunakan Sherlock."
    category = "username_osint"
    supported_targets = {TargetType.USERNAME}
    is_slow = True

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
        root_id = make_entity_id(target_type.value, target)

        with tempfile.TemporaryDirectory(prefix="sherlock_") as tmpdir:
            out_txt = Path(tmpdir) / "sherlock_found.txt"
            cmd = [
                sys.executable,
                "-m",
                "sherlock_project",
                target,
                "--timeout",
                str(ctx.config.sherlock_timeout),
                "--print-found",
                "--no-color",
                "--local",
                "--output",
                str(out_txt),
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_utf8_env(),
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=max(30, ctx.config.module_timeout - 5),
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                elapsed = int((time.perf_counter() - started) * 1000)
                return ModuleResult(
                    module_name=self.name,
                    display_name=self.display_name,
                    status="error",
                    duration_ms=elapsed,
                    error="Sherlock subprocess timed out",
                )

            seen_urls: set[str] = set()
            stdout_txt = stdout_b.decode("utf-8", errors="ignore")
            for match in re.finditer(r"\[\+\]\s+([^:]+):\s+(https?://\S+)", stdout_txt):
                site, url = match.group(1).strip(), match.group(2).strip()
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                findings.append(
                    Finding(
                        source=self.name,
                        category="social_profile",
                        title=f"Sherlock match: {site}",
                        value=url,
                        url=url,
                        severity=Severity.INFO,
                        confidence=0.85,
                        metadata={"site": site},
                    )
                )
                pid = make_entity_id("profile", f"sherlock:{site}:{target}")
                entities.append(EntityNode(id=pid, label=f"{site} ({target})", entity_type="profile"))
                edges.append(EntityEdge(source=root_id, target=pid, relation="has_account"))

            if out_txt.is_file():
                for line in out_txt.read_text(encoding="utf-8", errors="ignore").splitlines():
                    u = line.strip()
                    if u.startswith(("http://", "https://")) and u not in seen_urls:
                        seen_urls.add(u)
                        findings.append(
                            Finding(
                                source=self.name,
                                category="social_profile",
                                title="Sherlock profile URL",
                                value=u,
                                url=u,
                                severity=Severity.INFO,
                                confidence=0.82,
                            )
                        )
                        pid = make_entity_id("profile", u)
                        entities.append(EntityNode(id=pid, label=u, entity_type="profile"))
                        edges.append(EntityEdge(source=root_id, target=pid, relation="has_account"))

            err_txt = stderr_b.decode("utf-8", errors="ignore").strip()
            elapsed = int((time.perf_counter() - started) * 1000)
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                status="ok" if (proc.returncode == 0 or findings) else "partial",
                duration_ms=elapsed,
                findings=findings,
                entities=entities,
                edges=edges,
                summary=f"Sherlock menemukan {len(findings)} akun cocok.",
                error="" if findings or proc.returncode == 0 else err_txt[:300],
            )


class PublicProfileFastModule(BaseOSINTModule):
    """Fast API-free public profile intelligence (GitHub, Reddit, Keybase, Gravatar)."""

    name = "public_profiles"
    display_name = "Fast Public Profiles & Gravatar"
    description = "Lookup cepat GitHub (termasuk email commit publik), Reddit, Keybase, dan Gravatar."
    category = "username_osint"
    supported_targets = {TargetType.USERNAME, TargetType.EMAIL}
    is_slow = False

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

        if target_type == TargetType.EMAIL:
            await self._check_gravatar(target, root_id, ctx, findings, entities, edges, pivots)
        else:
            await asyncio.gather(
                self._check_github(target, root_id, ctx, findings, entities, edges, pivots),
                self._check_reddit(target, root_id, ctx, findings, entities, edges),
                self._check_keybase(target, root_id, ctx, findings, entities, edges, pivots),
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
            summary=f"Ditemukan {len(findings)} jejak profil publik cepat.",
            pivot_candidates=pivots,
        )

    async def _check_github(
        self,
        username: str,
        root_id: str,
        ctx: InvestigationContext,
        findings: list[Finding],
        entities: list[EntityNode],
        edges: list[EntityEdge],
        pivots: list[dict[str, str]],
    ) -> None:
        url = f"https://api.github.com/users/{quote(username)}"
        try:
            async with ctx.http_session.get(url) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
        except Exception:
            return

        html_url = data.get("html_url", f"https://github.com/{username}")
        name = data.get("name") or ""
        bio = data.get("bio") or ""
        email = data.get("email") or ""
        blog = data.get("blog") or ""
        created = data.get("created_at") or ""

        findings.append(
            Finding(
                source=self.name,
                category="social_profile",
                title="Akun GitHub Aktif",
                value=f"{html_url} | Name: {name or '-'} | Created: {created[:10]}",
                url=html_url,
                severity=Severity.INFO,
                confidence=0.98,
                verification_status="verified",
                metadata={"name": name, "bio": bio, "email": email, "blog": blog, "created_at": created},
            )
        )
        gid = make_entity_id("profile", f"github:{username}")
        entities.append(EntityNode(id=gid, label=f"GitHub: {username}", entity_type="profile"))
        edges.append(EntityEdge(source=root_id, target=gid, relation="has_account"))

        if name:
            pivots.append({"value": name, "type": "full_name", "reason": "Nama di profil GitHub"})
        if email:
            pivots.append({"value": email, "type": "email", "reason": "Email publik GitHub"})
            eid = make_entity_id("email", email)
            entities.append(EntityNode(id=eid, label=email, entity_type="email"))
            edges.append(EntityEdge(source=gid, target=eid, relation="uses_email"))

        # Check recent public push events for leaked commit author emails
        events_url = f"https://api.github.com/users/{quote(username)}/events/public?per_page=10"
        try:
            async with ctx.http_session.get(events_url) as ev_resp:
                if ev_resp.status == 200:
                    events = await ev_resp.json()
                    found_emails: set[str] = set()
                    for ev in events or []:
                        commits = (ev.get("payload") or {}).get("commits") or []
                        for c in commits:
                            author = c.get("author") or {}
                            c_email = str(author.get("email") or "").strip()
                            if c_email and "@" in c_email and "noreply.github.com" not in c_email:
                                found_emails.add(c_email)
                    for ce in sorted(found_emails):
                        findings.append(
                            Finding(
                                source=self.name,
                                category="identity_leak",
                                title="Email ditemukan di commit GitHub publik",
                                value=ce,
                                url=html_url,
                                severity=Severity.LOW,
                                confidence=0.9,
                            )
                        )
                        pivots.append({"value": ce, "type": "email", "reason": "Commit author email di GitHub"})
                        eid = make_entity_id("email", ce)
                        entities.append(EntityNode(id=eid, label=ce, entity_type="email"))
                        edges.append(EntityEdge(source=gid, target=eid, relation="commit_email"))
        except Exception:
            pass

    async def _check_reddit(
        self,
        username: str,
        root_id: str,
        ctx: InvestigationContext,
        findings: list[Finding],
        entities: list[EntityNode],
        edges: list[EntityEdge],
    ) -> None:
        url = f"https://www.reddit.com/user/{quote(username)}/about.json"
        try:
            async with ctx.http_session.get(url) as resp:
                if resp.status != 200:
                    return
                payload = await resp.json()
        except Exception:
            return
        data = (payload or {}).get("data") or {}
        if not data.get("name"):
            return
        profile_url = f"https://www.reddit.com/user/{data['name']}"
        karma = int(data.get("link_karma", 0)) + int(data.get("comment_karma", 0))
        findings.append(
            Finding(
                source=self.name,
                category="social_profile",
                title="Akun Reddit Ditemukan",
                value=f"{profile_url} (Total Karma: {karma})",
                url=profile_url,
                severity=Severity.INFO,
                confidence=0.92,
                metadata={"total_karma": karma},
            )
        )
        rid = make_entity_id("profile", f"reddit:{username}")
        entities.append(EntityNode(id=rid, label=f"Reddit: {data['name']}", entity_type="profile"))
        edges.append(EntityEdge(source=root_id, target=rid, relation="has_account"))

    async def _check_keybase(
        self,
        username: str,
        root_id: str,
        ctx: InvestigationContext,
        findings: list[Finding],
        entities: list[EntityNode],
        edges: list[EntityEdge],
        pivots: list[dict[str, str]],
    ) -> None:
        url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={quote(username)}"
        try:
            async with ctx.http_session.get(url) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
        except Exception:
            return
        them = data.get("them") or []
        if not them or not isinstance(them[0], dict):
            return
        user_obj = them[0]
        basics = user_obj.get("basics") or {}
        uname = basics.get("username")
        if not uname:
            return
        profile_url = f"https://keybase.io/{uname}"
        full_name = (user_obj.get("profile") or {}).get("full_name") or ""
        proofs = ((user_obj.get("proofs_summary") or {}).get("all") or [])
        proof_list = [f"{p.get('proof_type')}:{p.get('nametag')}" for p in proofs if isinstance(p, dict)]
        findings.append(
            Finding(
                source=self.name,
                category="social_profile",
                title="Profil & Verifikasi Kriptografi Keybase",
                value=f"{profile_url} | Proofs: {', '.join(proof_list[:6]) or 'none'}",
                url=profile_url,
                severity=Severity.INFO,
                confidence=0.95,
                metadata={"full_name": full_name, "proofs": proof_list},
            )
        )
        kid = make_entity_id("profile", f"keybase:{uname}")
        entities.append(EntityNode(id=kid, label=f"Keybase: {uname}", entity_type="profile"))
        edges.append(EntityEdge(source=root_id, target=kid, relation="has_account"))
        if full_name:
            pivots.append({"value": full_name, "type": "full_name", "reason": "Nama di profil Keybase"})

    async def _check_gravatar(
        self,
        email: str,
        root_id: str,
        ctx: InvestigationContext,
        findings: list[Finding],
        entities: list[EntityNode],
        edges: list[EntityEdge],
        pivots: list[dict[str, str]],
    ) -> None:
        md5_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
        url = f"https://en.gravatar.com/{md5_hash}.json"
        try:
            async with ctx.http_session.get(url) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
        except Exception:
            return
        entries = data.get("entry") or []
        if not entries:
            return
        entry = entries[0]
        profile_url = entry.get("profileUrl") or f"https://gravatar.com/{md5_hash}"
        display = entry.get("displayName") or entry.get("preferredUsername") or ""
        findings.append(
            Finding(
                source=self.name,
                category="social_profile",
                title="Profil Gravatar terhubung ke Email",
                value=f"{profile_url} (Display: {display or '-'})",
                url=profile_url,
                severity=Severity.INFO,
                confidence=0.92,
                metadata={"display_name": display, "md5": md5_hash},
            )
        )
        gid = make_entity_id("profile", f"gravatar:{md5_hash}")
        entities.append(EntityNode(id=gid, label=f"Gravatar: {display or md5_hash[:8]}", entity_type="profile"))
        edges.append(EntityEdge(source=root_id, target=gid, relation="linked_gravatar"))
        if display:
            p_type = "full_name" if " " in display else "username"
            pivots.append({"value": display, "type": p_type, "reason": "Nama/username dari Gravatar"})
