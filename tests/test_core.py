"""Unit tests, false-positive regression tests, and API smoke tests for OpenSearch — Yuhan's LAB v2.0."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from PIL import Image, PngImagePlugin

from opensearch_lab.core.base_module import InvestigationContext
from opensearch_lab.core.config import AppConfig
from opensearch_lab.core.correlator import make_entity_id
from opensearch_lab.core.detector import detect_target_type
from opensearch_lab.core.domain_utils import extract_registrable_domain, subdomain_depth
from opensearch_lab.core.models import (
    Finding,
    InvestigationReport,
    ModuleResult,
    Severity,
    TargetType,
)
from opensearch_lab.core.risk_scorer import RiskScorer
from opensearch_lab.core.storage import Storage
from opensearch_lab.core.text_extractor import ScamTextAnalyzer
from opensearch_lab.core.verifier import ResultVerifier
from opensearch_lab.modules.bank_intel import BankAccountModule
from opensearch_lab.modules.email_intel import EmailOsintModule
from opensearch_lab.modules.image_forensics import ImageForensicsModule
from opensearch_lab.modules.phone_intel import PhoneOsintModule
from opensearch_lab.modules.scam_intel import UrlPhishingModule
from opensearch_lab.modules.web_content_intel import WebContentAnalyzerModule
from opensearch_lab.reporting.exporter import ReportExporter
from opensearch_lab.web.app import create_app


class _FakeContent:
    def __init__(self, body: bytes) -> None:
        self._body = body

    async def read(self, n: int = -1) -> bytes:
        return self._body if n < 0 else self._body[:n]


class _FakeResponse:
    def __init__(self, status: int = 404, json_data=None, body: bytes = b"", headers=None) -> None:
        self.status = status
        self._json_data = json_data or {}
        self.content = _FakeContent(body)
        self.headers = headers or {"Content-Type": "text/html"}

    async def json(self, content_type=None):
        return self._json_data

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeHttpSession:
    def __init__(self, url_map=None) -> None:
        self.url_map = url_map or {}

    def get(self, url, *args, **kwargs):
        if url in self.url_map:
            return self.url_map[url]
        return _FakeResponse(status=404, json_data={})


class TestDetectorAndDomains(unittest.TestCase):
    def test_domain_utils_multi_part_tld(self) -> None:
        self.assertEqual(extract_registrable_domain("www.bca.co.id"), "bca.co.id")
        self.assertEqual(extract_registrable_domain("ib.bri.co.id"), "bri.co.id")
        self.assertEqual(subdomain_depth("www.bca.co.id"), 0)
        self.assertEqual(subdomain_depth("ib.bri.co.id"), 1)
        self.assertEqual(subdomain_depth("a.b.evil-login.xyz"), 2)

    def test_detect_all_core_types(self) -> None:
        self.assertEqual(detect_target_type("081234567890")[0], TargetType.PHONE)
        self.assertEqual(detect_target_type("81234567890")[0], TargetType.PHONE)
        self.assertEqual(detect_target_type("1500888"), (TargetType.PHONE, "1500888"))
        self.assertEqual(detect_target_type("+62 812-3456-7890"), (TargetType.PHONE, "+6281234567890"))
        self.assertEqual(detect_target_type("BCA 1234567890"), (TargetType.BANK_ACCOUNT, "BCA:1234567890"))
        self.assertEqual(detect_target_type("BRI:1234-0100-0123-501"), (TargetType.BANK_ACCOUNT, "BRI:123401000123501"))
        self.assertEqual(detect_target_type("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")[0], TargetType.CRYPTO_WALLET)
        self.assertEqual(detect_target_type("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")[0], TargetType.CRYPTO_WALLET)
        self.assertEqual(detect_target_type("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")[0], TargetType.CRYPTO_WALLET)
        self.assertEqual(detect_target_type("T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb")[0], TargetType.CRYPTO_WALLET)
        self.assertEqual(detect_target_type("1.1.1.1")[0], TargetType.IP)
        self.assertEqual(detect_target_type("cs.bri@gmail.com"), (TargetType.EMAIL, "cs.bri@gmail.com"))
        self.assertEqual(detect_target_type("http://hadiah-dana-resmi.xyz/login")[0], TargetType.URL)
        self.assertEqual(detect_target_type("example.com"), (TargetType.DOMAIN, "example.com"))
        self.assertEqual(detect_target_type("Budi Santoso"), (TargetType.FULL_NAME, "Budi Santoso"))
        self.assertEqual(detect_target_type("@yuhan_osint"), (TargetType.USERNAME, "yuhan_osint"))

    def test_detect_image_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            img_path = Path(tmp) / "sample.png"
            Image.new("RGB", (32, 32), color="red").save(img_path)
            ttype, norm = detect_target_type(str(img_path))
            self.assertEqual(ttype, TargetType.IMAGE_FILE)
            self.assertTrue(Path(norm).is_file())


class TestFalsePositiveRegressions(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = AppConfig.load()
        self.ctx = InvestigationContext(config=self.cfg, http_session=_FakeHttpSession())  # type: ignore[arg-type]

    def test_no_false_positive_brand_substrings(self) -> None:
        mod = UrlPhishingModule()
        for benign in (
            "perdana.co.id",
            "danamon.co.id",
            "bandana.com",
            "pineapple.com",
            "bridge-studio.com",
        ):
            res = asyncio.run(mod.run(benign, TargetType.DOMAIN, self.ctx))
            self.assertFalse(
                any(f.category == "brand_impersonation" for f in res.findings),
                f"False positive brand impersonation on {benign}",
            )

    def test_official_domains_score_zero(self) -> None:
        mod = UrlPhishingModule()
        for url in ("https://github.com/login", "https://www.bca.co.id"):
            res = asyncio.run(mod.run(url, TargetType.URL, self.ctx))
            assessment = RiskScorer.evaluate(res.findings)
            self.assertEqual(assessment.score, 0, f"Expected 0 on {url}, got {assessment.score}")
            self.assertEqual(assessment.level, "LOW")
            self.assertTrue(len(assessment.trust_signals) >= 1)

    def test_trust_discount_and_advisory_cap(self) -> None:
        findings = [
            Finding(source="shodan", category="shodan_ports", title="Port", value="3306", risk_delta=10, signal_tier="advisory"),
            Finding(source="ip_reputation", category="anonymizer", title="Proxy", value="VPN", risk_delta=10, signal_tier="advisory"),
            Finding(source="rdap_whois", category="trust_signal", title="Established 5y", value="5y", risk_delta=0, signal_tier="trust"),
            Finding(source="url_phishing", category="archive", title="Wayback", value="2020", risk_delta=0, signal_tier="trust"),
        ]
        assessment = RiskScorer.evaluate(findings)
        # Advisory capped at 15, then -20 trust discount => 0
        self.assertEqual(assessment.score, 0)
        self.assertEqual(assessment.level, "LOW")

    def test_profile_dedup_login_wall_and_soft404_filtering(self) -> None:
        findings = [
            Finding(source="maigret", category="social_profile", title="Profil di GitHub", value="https://github.com/alice", url="https://github.com/alice", metadata={"site": "GitHub"}),
            Finding(source="sherlock", category="social_profile", title="Sherlock GitHub", value="https://github.com/alice", url="https://github.com/alice", metadata={"site": "GitHub"}),
            Finding(source="maigret", category="social_profile", title="Profil di Facebook", value="https://www.facebook.com/alice", url="https://www.facebook.com/alice", metadata={"site": "Facebook"}),
            Finding(source="maigret", category="social_profile", title="Profil di SomeForum", value="https://forum.example/u/alice", url="https://forum.example/u/alice", metadata={"site": "SomeForum"}),
        ]
        pivots = [
            {"value": "Log in", "type": "full_name", "reason": "UI noise"},
            {"value": "admin", "type": "username", "reason": "Generic email local"},
            {"value": "alice_real", "type": "username", "reason": "Valid pivot"},
        ]
        deduped, clean_pivots = ResultVerifier.deduplicate_and_tag(findings, pivots)
        self.assertEqual(len(deduped), 3)
        self.assertEqual(len(clean_pivots), 1)
        self.assertEqual(clean_pivots[0]["value"], "alice_real")

        gh = next(f for f in deduped if "github.com/alice" in f.url)
        self.assertEqual(gh.verification_status, "corroborated")
        fb = next(f for f in deduped if "facebook.com/alice" in f.url)
        self.assertEqual(fb.verification_status, "unverified_login_wall")

        fake_sess = _FakeHttpSession(
            url_map={
                "https://github.com/alice": _FakeResponse(
                    status=200,
                    body=b"<html><head><title>Alice - GitHub</title></head><body>Profile</body></html>",
                ),
                "https://forum.example/u/alice": _FakeResponse(
                    status=200,
                    body=b"<html><head><title>User not found</title></head><body>Sorry, page not found</body></html>",
                ),
            }
        )
        kept, filtered = asyncio.run(ResultVerifier.verify_profile_urls(deduped, fake_sess))  # type: ignore[arg-type]
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].verification_status, "filtered_false_positive")
        self.assertFalse(any("forum.example" in f.url for f in kept))


class TestAntiScamModules(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = AppConfig.load()
        self.ctx = InvestigationContext(config=self.cfg, http_session=_FakeHttpSession())  # type: ignore[arg-type]

    def test_phone_indonesian_carrier_and_hotline(self) -> None:
        mod = PhoneOsintModule()
        res = asyncio.run(mod.run("81234567890", TargetType.PHONE, self.ctx))
        self.assertEqual(res.status, "ok")
        joined = " ".join(f.value for f in res.findings)
        self.assertIn("+6281234567890", joined)
        self.assertIn("Telkomsel", joined)
        self.assertTrue(any("wa.me/6281234567890" in f.url for f in res.findings))

        res_hot = asyncio.run(mod.run("1500888", TargetType.PHONE, self.ctx))
        self.assertTrue(any(f.signal_tier == "trust" and "Halo BCA" in f.value for f in res_hot.findings))

    def test_bank_account_module(self) -> None:
        mod = BankAccountModule()
        res = asyncio.run(mod.run("BCA:1234567890", TargetType.BANK_ACCOUNT, self.ctx))
        self.assertEqual(res.status, "ok")
        self.assertTrue(any("Sesuai standar" in f.value for f in res.findings))
        self.assertTrue(any("cekrekening.id" in f.url for f in res.findings))

    def test_email_disposable_and_impersonation(self) -> None:
        mod = EmailOsintModule()
        res_burn = asyncio.run(mod.run("penipu123@mailinator.com", TargetType.EMAIL, self.ctx))
        self.assertTrue(any(f.category == "burner_email" and f.risk_delta >= 30 for f in res_burn.findings))

        res_imp = asyncio.run(mod.run("cs.dana.resmi@gmail.com", TargetType.EMAIL, self.ctx))
        self.assertTrue(any(f.category == "brand_impersonation" and f.risk_delta >= 25 for f in res_imp.findings))

    def test_url_phishing_heuristics_and_typosquat(self) -> None:
        mod = UrlPhishingModule()
        res = asyncio.run(mod.run("http://hadiah-dana-resmi.xyz/login", TargetType.URL, self.ctx))
        assessment = RiskScorer.evaluate(res.findings)
        self.assertIn(assessment.level, {"HIGH", "CRITICAL"})
        self.assertGreaterEqual(assessment.score, 65)

        res_typo = asyncio.run(mod.run("https://bcaa-verify.top/otp", TargetType.URL, self.ctx))
        self.assertTrue(any(f.category == "brand_impersonation" for f in res_typo.findings))

    def test_web_content_phishing_kit_analyzer(self) -> None:
        mod = WebContentAnalyzerModule()
        evil_html = """
        <html>
          <head><title>BRImo - Login Bank BRI Resmi</title></head>
          <body>
            <form action="/submit">
              <input name="no_rekening" placeholder="Nomor Rekening" />
              <input name="pin_brimo" type="password" placeholder="PIN / OTP" />
            </form>
            <a href="https://wa.me/6281234567890">CS WA</a>
            <a href="https://t.me/cs_bri_palsu">Telegram</a>
            <script>
              fetch("https://api.telegram.org/bot12345678:AAFakeTokenSecret1234567890/sendMessage?chat_id=999");
            </script>
          </body>
        </html>
        """
        findings, entities, edges, pivots = [], [], [], []
        mod.analyze_html(
            html_text=evil_html,
            page_url="https://brimo-resmi-update.xyz/",
            host="brimo-resmi-update.xyz",
            root_id=make_entity_id("url", "https://brimo-resmi-update.xyz/"),
            findings=findings,
            entities=entities,
            edges=edges,
            pivots=pivots,
        )
        cats = {f.category for f in findings}
        self.assertIn("phishing_kit", cats)
        self.assertIn("brand_impersonation", cats)
        self.assertIn("credential_harvesting", cats)
        self.assertTrue(any(p["value"] == "+6281234567890" for p in pivots))
        self.assertTrue(any(p["value"] == "cs_bri_palsu" for p in pivots))

    def test_image_forensics_exif_xmp_dhash(self) -> None:
        mod = ImageForensicsModule()
        with tempfile.TemporaryDirectory() as tmp:
            # 1. Stripped EXIF -> zero risk penalty + dHash present
            clean_png = Path(tmp) / "wa_photo.png"
            Image.new("RGB", (64, 64), color="green").save(clean_png)
            res_clean = asyncio.run(mod.run(str(clean_png), TargetType.IMAGE_FILE, self.ctx))
            self.assertEqual(RiskScorer.evaluate(res_clean.findings).score, 0)
            self.assertTrue(any(e.entity_type == "image_dhash" for e in res_clean.entities))

            # 2. PNG chunk with Canva + Midjourney markers
            edited_png = Path(tmp) / "fake_receipt.png"
            meta = PngImagePlugin.PngInfo()
            meta.add_text("Software", "Canva Pro")
            meta.add_text("Description", "Generated with Midjourney")
            Image.new("RGB", (64, 64), color="blue").save(edited_png, pnginfo=meta)
            res_edit = asyncio.run(mod.run(str(edited_png), TargetType.IMAGE_FILE, self.ctx))
            cats = {f.category for f in res_edit.findings}
            self.assertIn("tamper_alert", cats)
            self.assertIn("ai_generated_alert", cats)

    def test_scam_text_analyzer(self) -> None:
        msg = (
            "Selamat! Segera buka undangan.apk atau klik http://hadiah-dana-resmi.xyz/login. "
            "Transfer biaya admin ke BCA 1234567890 dan konfirmasi WA 081234567890 atau @admin_dana_resmi."
        )
        res = ScamTextAnalyzer.analyze_text(msg)
        self.assertGreaterEqual(res["scam_score"], 75)
        self.assertEqual(res["risk_level"], "CRITICAL")
        ioc_vals = {i["value"] for i in res["iocs"]}
        self.assertIn("http://hadiah-dana-resmi.xyz/login", ioc_vals)
        self.assertIn("BCA:1234567890", ioc_vals)
        self.assertIn("081234567890", ioc_vals)
        self.assertIn("undangan.apk", ioc_vals)


class TestRiskStorageAndExporters(unittest.TestCase):
    def test_risk_scorer_consensus_and_watchlist(self) -> None:
        findings = [
            Finding(source="url_phishing", category="brand_impersonation", title="Fake BCA", value="x", severity=Severity.CRITICAL, risk_delta=35, signal_tier="confirmed_threat"),
            Finding(source="rdap_whois", category="scam_indicator", title="New Domain", value="3 days", severity=Severity.HIGH, risk_delta=30, signal_tier="suspicious"),
        ]
        matches = [{"match_kind": "watchlist", "indicator": "fake-bca.xyz", "label": "Scammer"}]
        assessment = RiskScorer.evaluate(findings, matches)
        self.assertEqual(assessment.score, 100)
        self.assertEqual(assessment.level, "CRITICAL")

    def test_storage_and_exports_backward_compat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            storage = Storage(tmp_dir / "test.db")
            wid = storage.add_watchlist("penipu.xyz", "domain", "Scammer", "Phishing")
            self.assertGreater(wid, 0)

            matches = storage.match_watchlist(["penipu.xyz"])
            report = InvestigationReport(
                case_id="CASE-TEST0001",
                query="penipu<script>.xyz",
                target_type=TargetType.DOMAIN,
                created_at="2026-11-23T10:00:00+00:00",
                duration_ms=123,
                modules_run=[ModuleResult("url_phishing", "URL Phishing", "ok", 50, summary="Tested")],
                findings=[
                    Finding(
                        source="url_phishing",
                        category="brand_impersonation",
                        title="Fake <script>alert(1)</script>",
                        value="Impersonation test & check",
                        severity=Severity.HIGH,
                        risk_delta=30,
                        signal_tier="confirmed_threat",
                    )
                ],
                risk=RiskScorer.evaluate([], matches),
                filtered_false_positives=[
                    Finding(source="maigret", category="social_profile", title="404", value="x", url="https://ex.com/404")
                ],
            )
            storage.save_case(report)
            loaded = storage.get_case("CASE-TEST0001")
            self.assertIsNotNone(loaded)
            self.assertEqual(len(loaded.filtered_false_positives), 1)  # type: ignore[union-attr]

            json_p = ReportExporter.export_by_format(report, "json", tmp_dir)
            md_p = ReportExporter.export_by_format(report, "md", tmp_dir)
            html_p = ReportExporter.export_by_format(report, "html", tmp_dir)
            pdf_p = ReportExporter.export_by_format(report, "pdf", tmp_dir)
            graph_p = ReportExporter.export_by_format(report, "graph", tmp_dir)

            for p in (json_p, md_p, html_p, pdf_p, graph_p):
                self.assertTrue(p.is_file())
                self.assertGreater(p.stat().st_size, 0)

            html_text = html_p.read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", html_text)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_text)
            self.assertTrue(pdf_p.read_bytes().startswith(b"%PDF"))


class TestWebDashboardApi(unittest.TestCase):
    def test_web_endpoints_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            cfg = AppConfig.load()
            cfg.db_path = tmp_dir / "web.db"
            cfg.reports_dir = tmp_dir / "reports"
            cfg.uploads_dir = tmp_dir / "uploads"
            app = create_app(cfg)
            client = app.test_client()

            self.assertEqual(client.get("/").status_code, 200)
            self.assertEqual(client.get("/api/health").status_code, 200)

            mods_res = client.get("/api/modules")
            self.assertEqual(mods_res.status_code, 200)
            self.assertEqual(len(mods_res.get_json()["modules"]), 17)

            det_res = client.get("/api/detect?q=BCA%201234567890")
            self.assertEqual(det_res.status_code, 200)
            self.assertEqual(det_res.get_json()["target_type"], "bank_account")

            txt_res = client.post(
                "/api/analyze-text",
                json={"text": "Buka undangan.apk atau transfer ke BCA 1234567890"},
            )
            self.assertEqual(txt_res.status_code, 200)
            self.assertGreaterEqual(txt_res.get_json()["scam_score"], 50)

            scan_bank = client.post(
                "/api/scan",
                json={"query": "BCA 1234567890", "target_type": "bank", "fast": True},
            )
            self.assertEqual(scan_bank.status_code, 200)
            self.assertEqual(scan_bank.get_json()["target_type"], "bank_account")

            wl_post = client.post(
                "/api/watchlist",
                json={"indicator": "scam@mailinator.com", "label": "Test Scammer", "reason": "Unit test"},
            )
            self.assertEqual(wl_post.status_code, 200)
            entry_id = wl_post.get_json()["id"]
            self.assertEqual(client.delete(f"/api/watchlist/{entry_id}").status_code, 200)


if __name__ == "__main__":
    unittest.main()
