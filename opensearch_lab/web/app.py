"""Flask web dashboard & REST API for OpenSearch — Yuhan's LAB."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from opensearch_lab import __app_name__, __version__
from opensearch_lab.core.config import AppConfig
from opensearch_lab.core.detector import IMAGE_EXTENSIONS, detect_target_type
from opensearch_lab.core.engine import InvestigationEngine
from opensearch_lab.core.storage import Storage
from opensearch_lab.core.text_extractor import ScamTextAnalyzer
from opensearch_lab.modules import create_default_registry
from opensearch_lab.reporting.exporter import ReportExporter
from opensearch_lab.reporting.graph_builder import build_graph_json, build_pyvis_html


def create_app(config: AppConfig | None = None) -> Flask:
    """Create and configure the Flask dashboard application."""
    cfg = config or AppConfig.load()
    cfg.ensure_directories()

    storage = Storage(cfg.db_path)
    registry = create_default_registry()
    engine = InvestigationEngine(config=cfg, registry=registry, storage=storage)

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.secret_key = cfg.get_env("OPENSEARCH_SECRET_KEY", "opensearch-yuhans-lab-local")
    app.config["MAX_CONTENT_LENGTH"] = cfg.max_upload_mb * 1024 * 1024

    def _serialize_report(report: Any) -> dict[str, Any]:
        data = report.to_dict()
        data["graph"] = build_graph_json(report)
        return data

    @app.get("/")
    def index() -> str:
        return render_template("index.html", app_name=__app_name__, version=__version__)

    @app.get("/api/health")
    def health() -> Response:
        return jsonify({"status": "ok", "app": __app_name__, "version": __version__})

    @app.get("/api/detect")
    def api_detect() -> Response:
        q = request.args.get("q", "")
        hint = request.args.get("type", "auto")
        ttype, norm = detect_target_type(q, hint=hint)
        return jsonify({"raw": q, "target_type": ttype.value, "normalized": norm})

    @app.get("/api/modules")
    def api_modules() -> Response:
        return jsonify(
            {
                "modules": registry.describe_all(cfg),
                "api_keys": cfg.api_key_status(),
            }
        )

    @app.post("/api/scan")
    def api_scan() -> tuple[Response, int] | Response:
        payload = request.get_json(silent=True) or {}
        query = str(payload.get("query", "")).strip()
        if not query:
            return jsonify({"error": "Target query tidak boleh kosong"}), 400

        target_type = str(payload.get("target_type", "auto")).strip()
        fast = bool(payload.get("fast", False))
        auto_pivot = bool(payload.get("auto_pivot", True))
        verify_profiles = bool(payload.get("verify_profiles", True))
        maigret_top = payload.get("maigret_top")
        if maigret_top is not None:
            try:
                maigret_top = max(10, min(500, int(maigret_top)))
            except (TypeError, ValueError):
                maigret_top = None
        modules_raw = payload.get("modules")
        include_modules = [str(m) for m in modules_raw] if isinstance(modules_raw, list) and modules_raw else None
        notes = str(payload.get("notes", ""))

        report = engine.investigate_sync(
            raw_query=query,
            target_hint=target_type,
            include_modules=include_modules,
            include_slow=not fast,
            auto_pivot=auto_pivot,
            maigret_top_sites=maigret_top,
            verify_profiles=verify_profiles,
            notes=notes,
        )
        return jsonify(_serialize_report(report))

    @app.post("/api/analyze-text")
    def api_analyze_text() -> tuple[Response, int] | Response:
        payload = request.get_json(silent=True) or {}
        text = str(payload.get("text", "")).strip()
        if not text:
            return jsonify({"error": "Teks pesan tidak boleh kosong"}), 400
        return jsonify(ScamTextAnalyzer.analyze_text(text))

    @app.post("/api/scan-image")
    def api_scan_image() -> tuple[Response, int] | Response:
        if "image" not in request.files:
            return jsonify({"error": "File gambar (field 'image') tidak ditemukan"}), 400
        file = request.files["image"]
        if not file or not file.filename:
            return jsonify({"error": "Nama file gambar kosong"}), 400

        safe_name = secure_filename(file.filename)
        ext = Path(safe_name).suffix.lower()
        if ext not in IMAGE_EXTENSIONS:
            return jsonify({"error": f"Ekstensi tidak didukung: {ext}. Gunakan JPG/PNG/WEBP/TIFF/GIF."}), 400

        dest_name = f"{uuid.uuid4().hex[:8]}_{safe_name}"
        dest_path = cfg.uploads_dir / dest_name
        file.save(str(dest_path))

        notes = str(request.form.get("notes", ""))
        report = engine.investigate_sync(
            raw_query=str(dest_path),
            target_hint="image",
            include_slow=False,
            auto_pivot=False,
            notes=notes,
        )
        return jsonify(_serialize_report(report))

    @app.get("/api/cases")
    def api_cases() -> Response:
        limit = min(200, max(1, int(request.args.get("limit", 40))))
        search = request.args.get("search", "")
        return jsonify({"cases": storage.list_cases(limit=limit, search=search)})

    @app.get("/api/cases/<case_id>")
    def api_get_case(case_id: str) -> tuple[Response, int] | Response:
        report = storage.get_case(case_id)
        if report is None:
            return jsonify({"error": "Case not found"}), 404
        return jsonify(_serialize_report(report))

    @app.post("/api/cases/<case_id>/notes")
    def api_update_notes(case_id: str) -> tuple[Response, int] | Response:
        payload = request.get_json(silent=True) or {}
        notes = str(payload.get("notes", ""))
        ok = storage.update_case_notes(case_id, notes)
        if not ok:
            return jsonify({"error": "Case not found"}), 404
        return jsonify({"status": "ok", "case_id": case_id, "notes": notes})

    @app.delete("/api/cases/<case_id>")
    def api_delete_case(case_id: str) -> tuple[Response, int] | Response:
        if not storage.delete_case(case_id):
            return jsonify({"error": "Case not found"}), 404
        return jsonify({"status": "deleted"})

    @app.get("/api/cases/<case_id>/graph")
    def api_case_graph(case_id: str) -> tuple[Response, int] | Response:
        report = storage.get_case(case_id)
        if report is None:
            return jsonify({"error": "Case not found"}), 404
        out_path = cfg.reports_dir / f"{report.case_id}_graph.html"
        build_pyvis_html(report, out_path)
        return send_file(str(out_path), mimetype="text/html")

    @app.get("/api/cases/<case_id>/export/<fmt>")
    def api_export_case(case_id: str, fmt: str) -> tuple[Response, int] | Response:
        report = storage.get_case(case_id)
        if report is None:
            return jsonify({"error": "Case not found"}), 404
        try:
            out_path = ReportExporter.export_by_format(report, fmt, cfg.reports_dir)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return send_file(str(out_path), as_attachment=True, download_name=out_path.name)

    @app.get("/api/watchlist")
    def api_watchlist_list() -> Response:
        return jsonify({"items": storage.list_watchlist()})

    @app.post("/api/watchlist")
    def api_watchlist_add() -> tuple[Response, int] | Response:
        payload = request.get_json(silent=True) or {}
        indicator = str(payload.get("indicator", "")).strip()
        if not indicator:
            return jsonify({"error": "Indicator tidak boleh kosong"}), 400
        hint = str(payload.get("indicator_type", "auto"))
        ttype, norm = detect_target_type(indicator, hint=hint)
        label = str(payload.get("label", "Confirmed Scammer")).strip() or "Confirmed Scammer"
        reason = str(payload.get("reason", "")).strip()
        entry_id = storage.add_watchlist(
            indicator=norm,
            indicator_type=ttype.value,
            label=label,
            reason=reason,
            source="web_ui",
        )
        return jsonify({"status": "ok", "id": entry_id, "indicator": norm, "indicator_type": ttype.value})

    @app.delete("/api/watchlist/<int:entry_id>")
    def api_watchlist_delete(entry_id: int) -> tuple[Response, int] | Response:
        if not storage.remove_watchlist(entry_id):
            return jsonify({"error": "Watchlist entry not found"}), 404
        return jsonify({"status": "deleted"})

    return app
