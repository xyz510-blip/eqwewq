"""Calibrated anti-scam & threat risk scoring engine with trust credit and tiered signals."""

from __future__ import annotations

from typing import Any

from opensearch_lab.core.models import Finding, RiskAssessment, RiskSignal, Severity


class RiskScorer:
    """Computes a bounded 0-100 risk assessment using tiered signals and trust verification."""

    @staticmethod
    def score_to_level(score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 45:
            return "HIGH"
        if score >= 20:
            return "MEDIUM"
        return "LOW"

    @classmethod
    def evaluate(
        cls,
        findings: list[Finding],
        watchlist_matches: list[dict[str, Any]] | None = None,
    ) -> RiskAssessment:
        signals: list[RiskSignal] = []
        trust_signals: list[dict[str, Any]] = []
        seen_keys: set[tuple[str, str, str]] = set()
        seen_trust_keys: set[tuple[str, str]] = set()

        confirmed_score = 0
        suspicious_score = 0
        advisory_raw_score = 0
        high_risk_sources: set[str] = set()
        has_trusted_domain = False

        for f in findings:
            # Collect explicit trust signals
            if f.signal_tier == "trust" or f.category in {"trusted_domain", "trust_signal"}:
                tkey = (f.source.lower(), f.title.lower())
                if tkey not in seen_trust_keys:
                    seen_trust_keys.add(tkey)
                    trust_signals.append(
                        {
                            "source": f.source,
                            "label": f.title,
                            "detail": f.value[:200],
                        }
                    )
                if f.category == "trusted_domain":
                    has_trusted_domain = True

            if f.risk_delta <= 0:
                continue

            dedup_key = (f.source.lower(), f.title.lower(), f.value.lower())
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            tier = f.signal_tier or "advisory"
            if tier == "confirmed_threat":
                confirmed_score += f.risk_delta
            elif tier == "suspicious":
                suspicious_score += f.risk_delta
            else:
                advisory_raw_score += f.risk_delta

            if f.severity in (Severity.HIGH, Severity.CRITICAL) and tier in {"confirmed_threat", "suspicious"}:
                high_risk_sources.add(f.source)

            signals.append(
                RiskSignal(
                    source=f.source,
                    label=f.title,
                    points=f.risk_delta,
                    severity=f.severity,
                    detail=f.value[:200],
                )
            )

        # Cap minor advisory signals combined at 15 points so weak hygiene alone never escalates risk
        advisory_score = min(15, advisory_raw_score)

        # Watchlist & cross-case correlation matches
        matches = watchlist_matches or []
        watchlist_hits = [m for m in matches if m.get("match_kind") == "watchlist"]
        cross_case_hits = [m for m in matches if m.get("match_kind") == "prior_case"]

        if watchlist_hits:
            pts = 35
            confirmed_score += pts
            indicators = ", ".join(str(m.get("indicator", "")) for m in watchlist_hits[:3])
            signals.append(
                RiskSignal(
                    source="watchlist",
                    label="Watchlist Penipu / Scammer Match",
                    points=pts,
                    severity=Severity.CRITICAL,
                    detail=f"Cocok dengan database watchlist lokal: {indicators}",
                )
            )

        if cross_case_hits:
            high_prior = [
                m
                for m in cross_case_hits
                if int(m.get("risk_score") or 0) >= 45
            ]
            if high_prior:
                pts = 15
                suspicious_score += pts
                prev_cases = ", ".join(str(m.get("case_id", "")) for m in high_prior[:3])
                signals.append(
                    RiskSignal(
                        source="correlation",
                        label="Terkait Kasus Berisiko Tinggi Sebelumnya",
                        points=pts,
                        severity=Severity.MEDIUM,
                        detail=f"Entitas terkait pernah tercatat berisiko tinggi di kasus: {prev_cases}",
                    )
                )

        # Multi-source high/critical consensus bonus
        if len(high_risk_sources) >= 2:
            pts = 15
            confirmed_score += pts
            signals.append(
                RiskSignal(
                    source="consensus",
                    label="Konsensus Multi-Modul Berisiko Tinggi",
                    points=pts,
                    severity=Severity.HIGH,
                    detail=f"Didukung {len(high_risk_sources)} sumber independen ({', '.join(sorted(high_risk_sources))})",
                )
            )

        raw_score = confirmed_score + suspicious_score + advisory_score

        # Apply trust calibration when no confirmed threat or watchlist hit is present
        if has_trusted_domain and confirmed_score == 0 and not watchlist_hits:
            raw_score = 0
            signals = []
        elif len(trust_signals) >= 2 and confirmed_score == 0 and not watchlist_hits:
            raw_score = max(0, raw_score - 20)

        final_score = max(0, min(100, raw_score))
        level = cls.score_to_level(final_score)

        # Sort signals descending by point weight
        signals.sort(key=lambda s: s.points, reverse=True)

        # Assessment confidence reflects presence of hard threat or trust proofs
        if watchlist_hits or len(high_risk_sources) >= 2 or has_trusted_domain:
            conf = 0.95
        elif confirmed_score > 0 or len(trust_signals) >= 2:
            conf = 0.9
        else:
            conf = 0.8

        summary = cls._build_summary(final_score, level, signals, trust_signals, len(findings))
        return RiskAssessment(
            score=final_score,
            level=level,
            signals=signals,
            summary=summary,
            trust_signals=trust_signals,
            confidence=conf,
        )

    @staticmethod
    def _build_summary(
        score: int,
        level: str,
        signals: list[RiskSignal],
        trust_signals: list[dict[str, Any]],
        total_findings: int,
    ) -> str:
        if not signals:
            if trust_signals:
                trust_labels = "; ".join(t["label"] for t in trust_signals[:2])
                return (
                    f"Skor risiko {score}/100 ({level}) dari {total_findings} temuan. "
                    f"Sinyal kepercayaan terverifikasi ({trust_labels}); tidak ditemukan indikasi penipuan."
                )
            return (
                f"Skor risiko {score}/100 ({level}) dari {total_findings} temuan. "
                "Tidak ditemukan red-flag otomatis yang kuat, namun tetap lakukan verifikasi manual."
            )
        top_labels = "; ".join(s.label for s in signals[:3])
        if level == "CRITICAL":
            verdict = "INDIKASI PENIPUAN / ANCAMAN SANGAT TINGGI — hindari transaksi atau interaksi sensitif."
        elif level == "HIGH":
            verdict = "BERISIKO TINGGI — ditemukan beberapa pola penipuan atau infrastruktur mencurigakan."
        elif level == "MEDIUM":
            verdict = "PERLU KEWASPADAAN — terdapat sinyal anomali yang perlu diverifikasi lebih lanjut."
        else:
            verdict = "RISIKO RENDAH — namun tetap validasi identitas lewat jalur resmi."

        return f"Skor {score}/100 ({level}). {verdict} Sinyal utama: {top_labels}."
