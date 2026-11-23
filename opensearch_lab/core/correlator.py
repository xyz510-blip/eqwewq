"""Entity correlation, deduplication, and result verification across OSINT modules."""

from __future__ import annotations

from opensearch_lab.core.models import (
    EntityEdge,
    EntityNode,
    Finding,
    ModuleResult,
    TargetType,
)
from opensearch_lab.core.verifier import ResultVerifier


def make_entity_id(entity_type: str, value: str) -> str:
    """Create a canonical node ID for the entity graph."""
    clean_val = value.strip().lower()
    return f"{entity_type.lower()}:{clean_val}"


class Correlator:
    """Deduplicates nodes, edges, findings, and pivot candidates across modules."""

    @staticmethod
    def correlate(
        root_target: str,
        root_type: TargetType,
        module_results: list[ModuleResult],
    ) -> tuple[list[Finding], list[EntityNode], list[EntityEdge], list[dict[str, str]]]:
        root_id = make_entity_id(root_type.value, root_target)
        nodes: dict[str, EntityNode] = {
            root_id: EntityNode(
                id=root_id,
                label=root_target,
                entity_type=root_type.value,
                metadata={"is_root": True},
            )
        }
        edges_map: dict[tuple[str, str, str], EntityEdge] = {}
        all_findings: list[Finding] = []
        seen_findings: set[tuple[str, str, str, str]] = set()
        pivot_map: dict[tuple[str, str], dict[str, str]] = {}

        for result in module_results:
            for finding in result.findings:
                fkey = (
                    finding.source.lower(),
                    finding.category.lower(),
                    finding.title.lower(),
                    finding.value.lower(),
                )
                if fkey not in seen_findings:
                    seen_findings.add(fkey)
                    all_findings.append(finding)

            for node in result.entities:
                existing = nodes.get(node.id)
                if existing is None:
                    nodes[node.id] = node
                else:
                    existing.metadata.update(node.metadata)

            for edge in result.edges:
                if edge.source not in nodes:
                    nodes[edge.source] = EntityNode(
                        id=edge.source,
                        label=edge.source.split(":", 1)[-1],
                        entity_type=edge.source.split(":", 1)[0] if ":" in edge.source else "entity",
                    )
                if edge.target not in nodes:
                    nodes[edge.target] = EntityNode(
                        id=edge.target,
                        label=edge.target.split(":", 1)[-1],
                        entity_type=edge.target.split(":", 1)[0] if ":" in edge.target else "entity",
                    )
                ekey = (edge.source, edge.target, edge.relation)
                if ekey not in edges_map:
                    edges_map[ekey] = edge

            for pivot in result.pivot_candidates:
                pval = str(pivot.get("value", "")).strip()
                ptype = str(pivot.get("type", "unknown")).strip()
                preason = str(pivot.get("reason", "")).strip()
                if not pval:
                    continue
                if pval.lower() == root_target.strip().lower() and ptype == root_type.value:
                    continue
                pkey = (ptype, pval.lower())
                if pkey not in pivot_map:
                    pivot_map[pkey] = {
                        "value": pval,
                        "type": ptype,
                        "reason": preason or f"Ditemukan oleh {result.display_name}",
                        "source": result.module_name,
                    }

        dedup_findings, clean_pivots = ResultVerifier.deduplicate_and_tag(
            all_findings, list(pivot_map.values())
        )

        return (
            dedup_findings,
            list(nodes.values()),
            list(edges_map.values()),
            clean_pivots,
        )
