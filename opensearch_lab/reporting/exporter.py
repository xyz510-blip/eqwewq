"""Multi-format investigation dossier exporter (JSON, Markdown, HTML, PDF)."""

from __future__ import annotations

import html
import json
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from opensearch_lab.core.models import InvestigationReport
from opensearch_lab.reporting.graph_builder import build_pyvis_html


class ReportExporter:
    """Exports an InvestigationReport into JSON, Markdown, HTML, PDF, and PyVis graph formats."""

    @staticmethod
    def export_json(report: InvestigationReport, output_path: Path | str) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        return out

    @staticmethod
    def export_markdown(report: InvestigationReport, output_path: Path | str) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        lines: list[str] = [
            f"# Laporan Investigasi OSINT — OpenSearch (Yuhan's LAB)",
            "",
            f"- **Case ID:** `{report.case_id}`",
            f"- **Target Query:** `{report.query}`",
            f"- **Target Type:** `{report.target_type.value}`",
            f"- **Waktu Investigasi (UTC):** `{report.created_at}`",
            f"- **Durasi Scan:** `{report.duration_ms} ms`",
            f"- **Skor Risiko Penipuan:** **{report.risk.score}/100 ({report.risk.level})**",
            "",
            f"> {report.risk.summary}",
            "",
        ]

        if report.notes:
            lines.extend(["## Catatan Investigator", "", report.notes, ""])

        if report.risk.trust_signals:
            lines.extend(["## Sinyal Kepercayaan & Legitimasi", ""])
            for ts in report.risk.trust_signals:
                lines.append(f"- **[TRUST]** `{ts.get('source')}` — **{ts.get('label')}**: {ts.get('detail')}")
            lines.append("")

        if report.watchlist_matches:
            lines.extend(["## Kecocokan Watchlist & Kasus Sebelumnya", ""])
            for m in report.watchlist_matches:
                if m.get("match_kind") == "watchlist":
                    lines.append(
                        f"- **[WATCHLIST]** `{m.get('indicator')}` — {m.get('label')} ({m.get('reason', '-')})"
                    )
                else:
                    lines.append(
                        f"- **[PRIOR CASE]** `{m.get('case_id')}` (Target: `{m.get('prior_query')}`, Risiko: {m.get('risk_score')}/100)"
                    )
            lines.append("")

        if report.risk.signals:
            lines.extend(
                [
                    "## Sinyal Red-Flag Penilaian Risiko",
                    "",
                    "| Poin | Severity | Sumber | Sinyal | Detail |",
                    "|---:|:---:|:---|:---|:---|",
                ]
            )
            for s in report.risk.signals:
                lines.append(
                    f"| +{s.points} | {s.severity.value.upper()} | {s.source} | {s.label} | {s.detail.replace('|', '/')} |"
                )
            lines.append("")

        lines.extend(["## Ringkasan Modul yang Dijalankan", ""])
        lines.append("| Modul | Status | Durasi (ms) | Temuan | Ringkasan |")
        lines.append("|:---|:---:|---:|---:|:---|")
        for m in report.modules_run:
            lines.append(
                f"| {m.display_name} (`{m.module_name}`) | {m.status} | {m.duration_ms} | {len(m.findings)} | {(m.summary or m.error).replace('|', '/')} |"
            )
        lines.append("")

        lines.extend([f"## Seluruh Temuan ({len(report.findings)})", ""])
        for idx, f in enumerate(report.findings, 1):
            url_part = f" — [Buka Tautan]({f.url})" if f.url else ""
            ver_part = f" `[{f.verification_status.upper()}]`" if f.verification_status != "unverified" else ""
            lines.append(
                f"{idx}. **[{f.severity.value.upper()}]**{ver_part} **{f.title}** (`{f.source}` / `{f.category}`): {f.value}{url_part}"
            )
        lines.append("")

        if report.filtered_false_positives:
            lines.extend([f"## False Positives Tersaring ({len(report.filtered_false_positives)})", ""])
            for fp in report.filtered_false_positives:
                lines.append(f"- `{fp.source}`: {fp.url or fp.title} — {fp.metadata.get('filter_reason', 'soft-404')}")
            lines.append("")

        if report.pivot_suggestions:
            lines.extend(["## Rekomendasi Pivot Investigasi Lanjutan", ""])
            for p in report.pivot_suggestions:
                lines.append(f"- `{p.get('type')}`: **`{p.get('value')}`** — {p.get('reason')}")
            lines.append("")

        out.write_text("\n".join(lines), encoding="utf-8")
        return out

    @staticmethod
    def export_html(report: InvestigationReport, output_path: Path | str) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        level_colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#10b981",
        }
        badge_color = level_colors.get(report.risk.level, "#06b6d4")

        signals_rows = "".join(
            f"<tr><td>+{s.points}</td><td><span class='sev sev-{html.escape(s.severity.value)}'>{html.escape(s.severity.value.upper())}</span></td>"
            f"<td>{html.escape(s.source)}</td><td>{html.escape(s.label)}</td><td>{html.escape(s.detail)}</td></tr>"
            for s in report.risk.signals
        ) or "<tr><td colspan='5'>Tidak ada sinyal red-flag berisiko.</td></tr>"

        finding_rows = "".join(
            f"<tr><td><span class='sev sev-{html.escape(f.severity.value)}'>{html.escape(f.severity.value.upper())}</span>"
            + (
                f"<div style='margin-top:4px;font-size:10px;color:#34d399'>{html.escape(f.verification_status.upper())}</div>"
                if f.verification_status in {"verified", "corroborated"}
                else (
                    "<div style='margin-top:4px;font-size:10px;color:#fbbf24'>LOGIN-WALL</div>"
                    if f.verification_status == "unverified_login_wall"
                    else ""
                )
            )
            + f"</td><td>{html.escape(f.source)}</td>"
            f"<td>{html.escape(f.title)}</td>"
            f"<td>{html.escape(f.value)}"
            + (
                f" <a href='{html.escape(f.url)}' target='_blank' rel='noopener noreferrer'>[Link]</a>"
                if f.url
                else ""
            )
            + "</td></tr>"
            for f in report.findings
        ) or "<tr><td colspan='4'>Tidak ada temuan.</td></tr>"

        trust_block = ""
        if report.risk.trust_signals:
            t_items = "".join(
                f"<li><strong>{html.escape(str(ts.get('label')))}</strong> ({html.escape(str(ts.get('source')))}) — {html.escape(str(ts.get('detail')))}</li>"
                for ts in report.risk.trust_signals
            )
            trust_block = f"<section class='card' style='border-color:#10b981;background:#0a1c19;'><h2>Sinyal Kepercayaan &amp; Legitimasi</h2><ul>{t_items}</ul></section>"

        fp_block = ""
        if report.filtered_false_positives:
            fp_items = "".join(
                f"<li>{html.escape(fp.url or fp.title)} — {html.escape(str(fp.metadata.get('filter_reason', 'soft-404')))}</li>"
                for fp in report.filtered_false_positives
            )
            fp_block = f"<section class='card'><h2>False Positives Tersaring ({len(report.filtered_false_positives)})</h2><ul>{fp_items}</ul></section>"

        pivots_html = "".join(
            f"<li><code>{html.escape(str(p.get('type')))}</code>: <strong>{html.escape(str(p.get('value')))}</strong> — {html.escape(str(p.get('reason')))}</li>"
            for p in report.pivot_suggestions
        ) or "<li>Tidak ada kandidat pivot tambahan.</li>"

        watchlist_block = ""
        if report.watchlist_matches:
            items = "".join(
                f"<li><strong>{html.escape(str(m.get('match_kind')))}</strong>: {html.escape(str(m.get('indicator')))} ({html.escape(str(m.get('label') or m.get('case_id', '')))})</li>"
                for m in report.watchlist_matches
            )
            watchlist_block = f"<section class='card alert'><h2>Watchlist & Korelasi Kasus</h2><ul>{items}</ul></section>"

        doc = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<title>Dossier {html.escape(report.case_id)} — {html.escape(report.query)}</title>
<style>
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #070d19; color: #e2e8f0; margin: 0; padding: 28px; line-height: 1.5; }}
  .wrap {{ max-width: 1120px; margin: auto; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px; }}
  .badge {{ background: {badge_color}; color: #070d19; font-weight: 800; padding: 10px 18px; border-radius: 10px; font-size: 18px; }}
  .card {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; padding: 18px 22px; margin-bottom: 20px; }}
  .card.alert {{ border-color: #ef4444; background: #1f1018; }}
  h1, h2 {{ margin-top: 0; color: #f8fafc; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid #1e293b; vertical-align: top; word-break: break-word; }}
  th {{ color: #94a3b8; font-weight: 600; }}
  a {{ color: #38bdf8; }}
  code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }}
  .sev {{ padding: 2px 7px; border-radius: 5px; font-size: 11px; font-weight: 700; }}
  .sev-critical {{ background: #7f1d1d; color: #fecaca; }}
  .sev-high {{ background: #7c2d12; color: #fed7aa; }}
  .sev-medium {{ background: #713f12; color: #fef08a; }}
  .sev-low {{ background: #064e3b; color: #a7f3d0; }}
  .sev-info {{ background: #1e293b; color: #cbd5e1; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div>
      <h1>OpenSearch — Yuhan's LAB Investigation Dossier</h1>
      <div>Case ID: <code>{html.escape(report.case_id)}</code> &bull; Target: <code>{html.escape(report.query)}</code> ({html.escape(report.target_type.value)}) &bull; {html.escape(report.created_at)}</div>
    </div>
    <div class="badge">RISK: {report.risk.score}/100 ({html.escape(report.risk.level)})</div>
  </div>
  <section class="card">
    <h2>Ringkasan Penilaian Risiko</h2>
    <p>{html.escape(report.risk.summary)}</p>
    {f"<p><strong>Catatan Investigator:</strong> {html.escape(report.notes)}</p>" if report.notes else ""}
  </section>
  {watchlist_block}
  {trust_block}
  <section class="card">
    <h2>Sinyal Red-Flag Risiko</h2>
    <table><thead><tr><th>Poin</th><th>Severity</th><th>Sumber</th><th>Sinyal</th><th>Detail</th></tr></thead><tbody>{signals_rows}</tbody></table>
  </section>
  <section class="card">
    <h2>Seluruh Temuan ({len(report.findings)})</h2>
    <table><thead><tr><th>Severity</th><th>Modul</th><th>Temuan</th><th>Nilai &amp; Bukti</th></tr></thead><tbody>{finding_rows}</tbody></table>
  </section>
  {fp_block}
  <section class="card">
    <h2>Rekomendasi Pivot Lanjutan</h2>
    <ul>{pivots_html}</ul>
  </section>
</div>
</body>
</html>"""
        out.write_text(doc, encoding="utf-8")
        return out

    @staticmethod
    def export_pdf(report: InvestigationReport, output_path: Path | str) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(out),
            pagesize=A4,
            leftMargin=16 * mm,
            rightMargin=16 * mm,
            topMargin=16 * mm,
            bottomMargin=16 * mm,
            title=f"OpenSearch Dossier {report.case_id}",
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "OSTitle", parent=styles["Heading1"], fontSize=16, textColor=colors.HexColor("#0f172a"), spaceAfter=6
        )
        h2_style = ParagraphStyle(
            "OSH2", parent=styles["Heading2"], fontSize=12, textColor=colors.HexColor("#1e293b"), spaceBefore=10, spaceAfter=4
        )
        body_style = ParagraphStyle(
            "OSBody", parent=styles["Normal"], fontSize=9, leading=12, textColor=colors.HexColor("#1e293b")
        )
        cell_style = ParagraphStyle(
            "OSCell", parent=styles["Normal"], fontSize=8, leading=10, textColor=colors.HexColor("#0f172a")
        )

        story = [
            Paragraph("OpenSearch — Yuhan's LAB: Anti-Scam OSINT Dossier", title_style),
            Paragraph(
                f"<b>Case ID:</b> {xml_escape(report.case_id)} &nbsp;|&nbsp; "
                f"<b>Target:</b> {xml_escape(report.query)} ({xml_escape(report.target_type.value)}) &nbsp;|&nbsp; "
                f"<b>Risk:</b> {report.risk.score}/100 ({xml_escape(report.risk.level)})",
                body_style,
            ),
            Paragraph(f"<b>Timestamp (UTC):</b> {xml_escape(report.created_at)} &nbsp;|&nbsp; <b>Duration:</b> {report.duration_ms} ms", body_style),
            Spacer(1, 6),
            Paragraph("Ringkasan Risiko", h2_style),
            Paragraph(xml_escape(report.risk.summary), body_style),
        ]

        if report.notes:
            story.extend([Paragraph("Catatan Investigator", h2_style), Paragraph(xml_escape(report.notes), body_style)])

        if report.risk.signals:
            story.append(Paragraph("Sinyal Red-Flag Risiko", h2_style))
            sig_rows = [[
                Paragraph("<b>Poin</b>", cell_style),
                Paragraph("<b>Severity</b>", cell_style),
                Paragraph("<b>Sinyal</b>", cell_style),
                Paragraph("<b>Detail</b>", cell_style),
            ]]
            for s in report.risk.signals[:25]:
                sig_rows.append([
                    Paragraph(f"+{s.points}", cell_style),
                    Paragraph(xml_escape(s.severity.value.upper()), cell_style),
                    Paragraph(xml_escape(s.label), cell_style),
                    Paragraph(xml_escape(s.detail[:180]), cell_style),
                ])
            t = Table(sig_rows, colWidths=[14 * mm, 22 * mm, 52 * mm, 88 * mm])
            t.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ])
            )
            story.extend([t, Spacer(1, 6)])

        story.append(Paragraph(f"Daftar Temuan ({len(report.findings)})", h2_style))
        find_rows = [[
            Paragraph("<b>Sev</b>", cell_style),
            Paragraph("<b>Modul</b>", cell_style),
            Paragraph("<b>Judul</b>", cell_style),
            Paragraph("<b>Nilai / Bukti</b>", cell_style),
        ]]
        for f in report.findings[:60]:
            val_text = f.value[:220] + (f"\n{f.url}" if f.url else "")
            find_rows.append([
                Paragraph(xml_escape(f.severity.value.upper()), cell_style),
                Paragraph(xml_escape(f.source), cell_style),
                Paragraph(xml_escape(f.title[:80]), cell_style),
                Paragraph(xml_escape(val_text), cell_style),
            ])
        ft = Table(find_rows, colWidths=[18 * mm, 28 * mm, 48 * mm, 82 * mm])
        ft.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(ft)

        doc.build(story)
        return out

    @classmethod
    def export_by_format(
        cls,
        report: InvestigationReport,
        fmt: str,
        reports_dir: Path | str,
    ) -> Path:
        """Export report to the given format inside reports_dir and return the generated Path."""
        base_dir = Path(reports_dir)
        base_dir.mkdir(parents=True, exist_ok=True)
        norm_fmt = fmt.strip().lower()
        stem = report.case_id

        if norm_fmt == "json":
            return cls.export_json(report, base_dir / f"{stem}.json")
        if norm_fmt in ("md", "markdown"):
            return cls.export_markdown(report, base_dir / f"{stem}.md")
        if norm_fmt == "html":
            return cls.export_html(report, base_dir / f"{stem}.html")
        if norm_fmt == "pdf":
            return cls.export_pdf(report, base_dir / f"{stem}.pdf")
        if norm_fmt == "graph":
            return build_pyvis_html(report, base_dir / f"{stem}_graph.html")
        raise ValueError(f"Format ekspor tidak didukung: {fmt}")
