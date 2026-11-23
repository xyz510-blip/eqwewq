"""Person full-name intelligence: username alias generator and targeted person dorks."""

from __future__ import annotations

import re
import time
from urllib.parse import quote

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.correlator import make_entity_id
from opensearch_lab.core.models import (
    EntityEdge,
    EntityNode,
    Finding,
    ModuleResult,
    Severity,
    TargetType,
)


def generate_username_permutations(full_name: str, limit: int = 10) -> list[str]:
    """Generate probable social media username variants from a person's full name."""
    cleaned = re.sub(r"[^a-zA-Z\s]", "", full_name).lower().strip()
    parts = [p for p in cleaned.split() if p]
    if not parts:
        return []
    candidates: list[str] = []
    if len(parts) == 1:
        p = parts[0]
        candidates.extend([p, f"{p}_official", f"real_{p}"])
    else:
        first, last = parts[0], parts[-1]
        joined = "".join(parts)
        dotted = ".".join(parts)
        underscored = "_".join(parts)
        candidates.extend(
            [
                joined,
                dotted,
                underscored,
                f"{first}{last}",
                f"{first}.{last}",
                f"{first}_{last}",
                f"{first[0]}{last}",
                f"{first[0]}_{last}",
                f"{first}{last[0]}",
                f"{last}{first}",
            ]
        )
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if len(c) >= 3 and c not in seen:
            seen.add(c)
            unique.append(c)
        if len(unique) >= limit:
            break
    return unique


class PersonAliasModule(BaseOSINTModule):
    """Generates username pivot candidates and cross-platform person search dorks."""

    name = "person_alias"
    display_name = "Person Name & Alias Pivot Engine"
    description = "Membuat permutasi username kandidat untuk Maigret/Sherlock serta dork profil publik & berita penipuan."
    category = "identity_osint"
    supported_targets = {TargetType.FULL_NAME}

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

        variants = generate_username_permutations(target, limit=10)
        if variants:
            findings.append(
                Finding(
                    source=self.name,
                    category="alias_generation",
                    title="Kandidat Username untuk Pivot Maigret/Sherlock",
                    value=", ".join(variants),
                    severity=Severity.INFO,
                    confidence=0.8,
                    metadata={"variants": variants},
                )
            )
            for v in variants[:6]:
                uid = make_entity_id("username", v)
                entities.append(EntityNode(id=uid, label=v, entity_type="username"))
                edges.append(EntityEdge(source=root_id, target=uid, relation="possible_alias"))
                pivots.append(
                    {
                        "value": v,
                        "type": "username",
                        "reason": f"Permutasi username dari nama '{target}'",
                    }
                )

        q_name = quote(f'"{target}"')
        dorks = [
            ("LinkedIn People Search", f"https://www.google.com/search?q=site:linkedin.com/in+{q_name}", "Cek rekam jejak karier/identitas profesional"),
            ("Instagram & TikTok Mention", f"https://www.google.com/search?q=(site:instagram.com+OR+site:tiktok.com)+{q_name}", "Cari profil media sosial dengan nama asli"),
            ("Facebook Profile Search", f"https://www.google.com/search?q=site:facebook.com+{q_name}", "Cari akun Facebook terkait"),
            ("Berita Hukum / Penipuan / OJK", f"https://www.google.com/search?q={q_name}+(penipu+OR+penipuan+OR+tersangka+OR+polisi+OR+ojk)", "Cek pemberitaan atau laporan publik"),
        ]
        for title, url, desc in dorks:
            findings.append(
                Finding(
                    source=self.name,
                    category="investigation_link",
                    title=title,
                    value=desc,
                    url=url,
                    severity=Severity.INFO,
                    confidence=1.0,
                )
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
            summary=f"Dibuat {len(variants)} kandidat alias dan {len(dorks)} tautan pencarian identitas.",
            pivot_candidates=pivots,
        )
