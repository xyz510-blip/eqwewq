"""Command-line interface for OpenSearch — Yuhan's LAB."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from colorama import Fore, Style
from colorama import init as colorama_init

from opensearch_lab import __app_name__, __version__
from opensearch_lab.core.config import AppConfig
from opensearch_lab.core.detector import detect_target_type
from opensearch_lab.core.engine import InvestigationEngine
from opensearch_lab.core.models import InvestigationReport
from opensearch_lab.core.storage import Storage
from opensearch_lab.core.text_extractor import ScamTextAnalyzer
from opensearch_lab.modules import create_default_registry
from opensearch_lab.reporting.exporter import ReportExporter


def _configure_stdio() -> None:
    """Prevent UnicodeEncodeError on Windows cp1252 terminals."""
    colorama_init(autoreset=True)
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if callable(reconf):
            try:
                reconf(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _build_runtime() -> tuple[AppConfig, Storage, InvestigationEngine]:
    config = AppConfig.load()
    config.ensure_directories()
    storage = Storage(config.db_path)
    registry = create_default_registry()
    engine = InvestigationEngine(config=config, registry=registry, storage=storage)
    return config, storage, engine


def _risk_color(level: str) -> str:
    return {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.GREEN,
    }.get(level, Fore.CYAN)


def _sev_color(sev: str) -> str:
    return {
        "critical": Fore.RED + Style.BRIGHT,
        "high": Fore.RED,
        "medium": Fore.YELLOW,
        "low": Fore.GREEN,
        "info": Fore.CYAN,
    }.get(sev.lower(), Fore.WHITE)


def _print_banner() -> None:
    click.echo(f"{Fore.CYAN}{Style.BRIGHT}============================================================")
    click.echo(f"{Fore.CYAN}{Style.BRIGHT}  {__app_name__} v{__version__}")
    click.echo(f"{Fore.WHITE}  OSINT & Anti-Scam Investigation Framework")
    click.echo(f"{Fore.CYAN}{Style.BRIGHT}============================================================")


def _print_report(report: InvestigationReport) -> None:
    r_col = _risk_color(report.risk.level)
    click.echo("")
    click.echo(f"{Fore.WHITE}{Style.BRIGHT}Case ID     : {Fore.CYAN}{report.case_id}")
    click.echo(f"{Fore.WHITE}{Style.BRIGHT}Target      : {Fore.WHITE}{report.query} ({report.target_type.value})")
    fp_info = f" | Filtered FP: {len(report.filtered_false_positives)}" if report.filtered_false_positives else ""
    click.echo(f"{Fore.WHITE}{Style.BRIGHT}Duration    : {report.duration_ms} ms | Entities: {len(report.entities)} | Findings: {len(report.findings)}{fp_info}")
    click.echo(f"{Fore.WHITE}{Style.BRIGHT}Risk Score  : {r_col}{report.risk.score}/100 [{report.risk.level}]{Style.RESET_ALL}")
    click.echo(f"{Fore.WHITE}{report.risk.summary}")

    if report.risk.trust_signals:
        click.echo(f"\n{Fore.GREEN}{Style.BRIGHT}[+] TRUST / LEGITIMACY SIGNALS ({len(report.risk.trust_signals)}):")
        for ts in report.risk.trust_signals:
            click.echo(f"  - [TRUST] {ts.get('label')} ({ts.get('source')}) -> {ts.get('detail')}")

    if report.watchlist_matches:
        click.echo(f"\n{Fore.RED}{Style.BRIGHT}[!] WATCHLIST / PRIOR CASE MATCHES ({len(report.watchlist_matches)}):")
        for m in report.watchlist_matches:
            if m.get("match_kind") == "watchlist":
                click.echo(f"  - [WATCHLIST] {m.get('indicator')} -> {m.get('label')} ({m.get('reason', '-')})")
            else:
                click.echo(f"  - [PRIOR CASE] {m.get('case_id')} (Target: {m.get('prior_query')}, Risk: {m.get('risk_score')}/100)")

    if report.risk.signals:
        click.echo(f"\n{Fore.YELLOW}{Style.BRIGHT}[!] RED FLAGS / RISK SIGNALS:")
        for sig in report.risk.signals:
            scol = _sev_color(sig.severity.value)
            click.echo(f"  +{sig.points:>2} pts {scol}[{sig.severity.value.upper()}]{Style.RESET_ALL} {sig.label} ({sig.source}) -> {sig.detail}")

    click.echo(f"\n{Fore.CYAN}{Style.BRIGHT}[*] MODULE SUMMARY:")
    for mod in report.modules_run:
        st_col = Fore.GREEN if mod.status == "ok" else (Fore.YELLOW if mod.status == "partial" else Fore.RED)
        msg = mod.summary or mod.error
        click.echo(f"  - {mod.display_name} [{st_col}{mod.status}{Style.RESET_ALL}, {mod.duration_ms}ms]: {msg}")

    click.echo(f"\n{Fore.CYAN}{Style.BRIGHT}[*] FINDINGS ({len(report.findings)}):")
    for idx, f in enumerate(report.findings, 1):
        scol = _sev_color(f.severity.value)
        v_badge = ""
        if f.verification_status in {"verified", "corroborated"}:
            v_badge = f" {Fore.GREEN}[{f.verification_status.upper()}]{Style.RESET_ALL}"
        elif f.verification_status == "unverified_login_wall":
            v_badge = f" {Fore.YELLOW}[LOGIN-WALL]{Style.RESET_ALL}"
        url_str = f" | {Fore.BLUE}{f.url}{Style.RESET_ALL}" if f.url else ""
        click.echo(f"  {idx:>2}. {scol}[{f.severity.value.upper()}]{Style.RESET_ALL}{v_badge} [{f.source}] {Style.BRIGHT}{f.title}{Style.RESET_ALL}: {f.value}{url_str}")

    if report.filtered_false_positives:
        click.echo(f"\n{Fore.YELLOW}[~] Filtered Soft-404 / False Positives ({len(report.filtered_false_positives)}): "
                   + ", ".join(fp.url or fp.title for fp in report.filtered_false_positives[:5]))

    if report.pivot_suggestions:
        click.echo(f"\n{Fore.MAGENTA}{Style.BRIGHT}[>] RECOMMENDED PIVOTS:")
        for p in report.pivot_suggestions[:12]:
            click.echo(f"  - ({p.get('type')}) {p.get('value')} — {p.get('reason')}")


@click.group()
def cli() -> None:
    """OpenSearch — Yuhan's LAB OSINT & Anti-Scam Investigation CLI."""
    _configure_stdio()


@cli.command()
@click.argument("target")
@click.option(
    "--type",
    "target_type",
    default="auto",
    help="Target type: auto, username, email, phone, bank, domain, ip, url, crypto, image, name.",
)
@click.option(
    "--modules",
    default="",
    help="Comma-separated list of module names to run (default: all matching).",
)
@click.option(
    "--fast",
    is_flag=True,
    default=False,
    help="Skip slow username brute-force modules (Maigret/Sherlock).",
)
@click.option(
    "--no-pivot",
    is_flag=True,
    default=False,
    help="Disable automatic depth-1 infrastructure/email pivoting.",
)
@click.option(
    "--no-verify",
    is_flag=True,
    default=False,
    help="Skip live HTTP soft-404 verification for discovered social profiles.",
)
@click.option(
    "--maigret-top",
    type=int,
    default=None,
    help="Override Maigret --top-sites count (default from config.yaml).",
)
@click.option(
    "--export",
    "export_formats",
    default="",
    help="Comma-separated export formats: json,md,html,pdf,graph.",
)
@click.option("--notes", default="", help="Initial investigator notes for this case.")
def scan(
    target: str,
    target_type: str,
    modules: str,
    fast: bool,
    no_pivot: bool,
    no_verify: bool,
    maigret_top: int | None,
    export_formats: str,
    notes: str,
) -> None:
    """Run an OSINT & anti-scam investigation against TARGET."""
    _print_banner()
    config, _, engine = _build_runtime()
    detected_type, norm_target = detect_target_type(target, hint=target_type)
    include_mods = [m.strip() for m in modules.split(",") if m.strip()] if modules else None

    click.echo(f"{Fore.CYAN}[+] Starting scan on '{norm_target}' (detected type: {detected_type.value})...")
    report = engine.investigate_sync(
        raw_query=target,
        target_hint=target_type,
        include_modules=include_mods,
        include_slow=not fast,
        auto_pivot=not no_pivot,
        maigret_top_sites=maigret_top,
        verify_profiles=not no_verify,
        notes=notes,
    )
    _print_report(report)

    if export_formats:
        click.echo(f"\n{Fore.CYAN}{Style.BRIGHT}[*] EXPORTING REPORTS:")
        for fmt in [x.strip() for x in export_formats.split(",") if x.strip()]:
            try:
                out_path = ReportExporter.export_by_format(report, fmt, config.reports_dir)
                click.echo(f"  - {fmt.upper()}: {out_path}")
            except Exception as exc:
                click.echo(f"  - {Fore.RED}{fmt.upper()} failed: {exc}")


@cli.command("analyze-text")
@click.argument("text", required=False, default="")
@click.option("--file", "file_path", default="", help="Read chat/SMS log from a UTF-8 text file.")
@click.option("--scan-all", is_flag=True, default=False, help="Automatically scan extracted scannable IOCs.")
@click.option("--fast", is_flag=True, default=True, help="Use fast mode when batch-scanning IOCs.")
def analyze_text_cmd(text: str, file_path: str, scan_all: bool, fast: bool) -> None:
    """Analyze suspicious chat/SMS/DM text for scam modus & extract IOCs."""
    _print_banner()
    raw = text
    if file_path:
        p = Path(file_path)
        if not p.is_file():
            click.echo(f"{Fore.RED}File tidak ditemukan: {file_path}")
            sys.exit(1)
        raw = p.read_text(encoding="utf-8", errors="ignore")
    if not raw.strip():
        click.echo(f"{Fore.RED}Masukkan teks atau --file untuk dianalisis.")
        sys.exit(1)

    res = ScamTextAnalyzer.analyze_text(raw)
    r_col = _risk_color(res["risk_level"])
    click.echo(f"\n{Fore.WHITE}{Style.BRIGHT}Scam Risk Score : {r_col}{res['scam_score']}/100 [{res['risk_level']}]{Style.RESET_ALL}")

    if res["matched_modi"]:
        click.echo(f"\n{Fore.RED}{Style.BRIGHT}[!] TERDETEKSI MODUS PENIPUAN:")
        for m in res["matched_modi"]:
            click.echo(f"  - [{m['severity'].upper()}] {m['name']} (Keywords: {', '.join(m['matched_keywords'])})")

    if res["iocs"]:
        click.echo(f"\n{Fore.CYAN}{Style.BRIGHT}[*] IOC / BUKTI TEREKSTRAK ({len(res['iocs'])}):")
        for item in res["iocs"]:
            click.echo(f"  - [{item['type']}] {item['value']} ({item['label']})")
    else:
        click.echo(f"\n{Fore.YELLOW}Tidak ada IOC (URL/HP/Rekening/Email/Wallet) terdeteksi.")

    click.echo(f"\n{Fore.GREEN}{Style.BRIGHT}[+] REKOMENDASI:")
    for rec in res["recommendations"]:
        click.echo(f"  - {rec}")

    if scan_all and res["iocs"]:
        _, _, engine = _build_runtime()
        scannable = [i for i in res["iocs"] if i["type"] != "artifact"][:6]
        click.echo(f"\n{Fore.CYAN}{Style.BRIGHT}[*] BATCH SCANNING {len(scannable)} IOC:")
        for item in scannable:
            rep = engine.investigate_sync(
                raw_query=item["value"],
                target_hint=item["type"],
                include_slow=not fast,
                auto_pivot=False,
            )
            rc = _risk_color(rep.risk.level)
            click.echo(f"  -> {item['value']} ({rep.target_type.value}) | {rc}{rep.risk.score}/100 [{rep.risk.level}]{Style.RESET_ALL} | Case: {rep.case_id}")


@cli.command("modules")
def list_modules_cmd() -> None:
    """List all registered OSINT modules and API key status."""
    _print_banner()
    config, _, engine = _build_runtime()
    mods = engine.registry.describe_all(config)
    click.echo(f"\n{Fore.CYAN}{Style.BRIGHT}Registered OSINT Modules ({len(mods)}):")
    for m in mods:
        speed = "SLOW" if m["is_slow"] else "FAST"
        avail = f"{Fore.GREEN}READY" if m["available"] else f"{Fore.RED}UNAVAILABLE"
        targets = ", ".join(m["supported_targets"])  # type: ignore[arg-type]
        click.echo(f"  - {Style.BRIGHT}{m['name']:<16}{Style.RESET_ALL} [{avail}{Style.RESET_ALL} | {speed}] ({m['key_status']})")
        click.echo(f"    Targets: {targets}")
        click.echo(f"    {m['description']}")


@cli.command()
@click.option("--limit", default=20, show_default=True, help="Maximum cases to display.")
@click.option("--search", default="", help="Search cases by query, notes, or case ID.")
def history(limit: int, search: str) -> None:
    """Show saved investigation case history."""
    _print_banner()
    _, storage, _ = _build_runtime()
    rows = storage.list_cases(limit=limit, search=search)
    if not rows:
        click.echo(f"{Fore.YELLOW}Belum ada riwayat kasus tersimpan.")
        return
    click.echo(f"\n{Fore.CYAN}{Style.BRIGHT}Investigation History ({len(rows)}):")
    for r in rows:
        rc = _risk_color(str(r["risk_level"]))
        click.echo(
            f"  {Fore.CYAN}{r['case_id']}{Style.RESET_ALL} | {rc}{r['risk_score']:>3}/100 [{r['risk_level']:<8}]{Style.RESET_ALL} | "
            f"{r['target_type']:<13} | {r['query']} ({str(r['created_at'])[:19]})"
        )


@cli.command()
@click.argument("case_id")
@click.option("--export", "export_formats", default="", help="Comma-separated export formats: json,md,html,pdf,graph.")
def case(case_id: str, export_formats: str) -> None:
    """View or export a previously saved investigation case."""
    _print_banner()
    config, storage, _ = _build_runtime()
    report = storage.get_case(case_id)
    if report is None:
        click.echo(f"{Fore.RED}Case ID '{case_id}' tidak ditemukan.")
        sys.exit(1)
    _print_report(report)
    if export_formats:
        click.echo(f"\n{Fore.CYAN}{Style.BRIGHT}[*] EXPORTING REPORTS:")
        for fmt in [x.strip() for x in export_formats.split(",") if x.strip()]:
            out_path = ReportExporter.export_by_format(report, fmt, config.reports_dir)
            click.echo(f"  - {fmt.upper()}: {out_path}")


@cli.group()
def watchlist() -> None:
    """Manage local scammer indicator watchlist."""


@watchlist.command("add")
@click.argument("indicator")
@click.option("--type", "indicator_type", default="auto", help="Indicator type (auto/phone/email/domain/username/crypto).")
@click.option("--label", default="Confirmed Scammer", show_default=True, help="Short label.")
@click.option("--reason", default="", help="Case details or scam modus.")
def watchlist_add(indicator: str, indicator_type: str, label: str, reason: str) -> None:
    """Add an indicator to the local scammer watchlist."""
    _, storage, _ = _build_runtime()
    ttype, norm = detect_target_type(indicator, hint=indicator_type)
    entry_id = storage.add_watchlist(
        indicator=norm,
        indicator_type=ttype.value,
        label=label,
        reason=reason,
    )
    click.echo(f"{Fore.GREEN}[+] Watchlist entry #{entry_id} saved: '{norm}' ({ttype.value}) -> {label}")


@watchlist.command("list")
def watchlist_list() -> None:
    """List all indicators in the local scammer watchlist."""
    _, storage, _ = _build_runtime()
    entries = storage.list_watchlist()
    if not entries:
        click.echo(f"{Fore.YELLOW}Watchlist kosong.")
        return
    click.echo(f"\n{Fore.CYAN}{Style.BRIGHT}Local Scammer Watchlist ({len(entries)}):")
    for e in entries:
        click.echo(f"  #{e['id']:<3} | {e['indicator']:<28} | {e['indicator_type']:<13} | {e['label']} — {e['reason']}")


@watchlist.command("remove")
@click.argument("entry_id", type=int)
def watchlist_remove(entry_id: int) -> None:
    """Remove a watchlist entry by numeric ID."""
    _, storage, _ = _build_runtime()
    if storage.remove_watchlist(entry_id):
        click.echo(f"{Fore.GREEN}[+] Watchlist entry #{entry_id} removed.")
    else:
        click.echo(f"{Fore.RED}Entry #{entry_id} not found.")


@cli.command()
@click.option("--host", default=None, help="Bind host (default 127.0.0.1).")
@click.option("--port", type=int, default=None, help="Bind port (default 5000).")
def web(host: str | None, port: int | None) -> None:
    """Launch the local OpenSearch Web Dashboard."""
    from opensearch_lab.web.app import create_app

    _print_banner()
    config = AppConfig.load()
    bind_host = host or config.web_host
    bind_port = port or config.web_port
    app = create_app(config)
    click.echo(f"{Fore.GREEN}[*] Starting Web Dashboard at http://{bind_host}:{bind_port}")
    app.run(host=bind_host, port=bind_port, debug=False)
