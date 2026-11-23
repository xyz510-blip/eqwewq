"""Application configuration loader combining config.yaml, .env, and os.environ."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

API_KEY_ENV_VARS: tuple[str, ...] = (
    "SHODAN_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "HIBP_API_KEY",
    "HUNTER_API_KEY",
    "IPINFO_TOKEN",
    "URLSCAN_API_KEY",
    "NUMVERIFY_API_KEY",
    "ETHERSCAN_API_KEY",
)


def _parse_dotenv(dotenv_path: Path) -> dict[str, str]:
    """Parse key=value pairs from a .env file without external dependencies."""
    parsed: dict[str, str] = {}
    if not dotenv_path.is_file():
        return parsed
    for raw_line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and ((val[0] == val[-1] == '"') or (val[0] == val[-1] == "'")):
            val = val[1:-1]
        if key:
            parsed[key] = val
    return parsed


@dataclass
class AppConfig:
    """Resolved runtime configuration for OpenSearch — Yuhan's LAB."""

    root_dir: Path
    app_name: str = "OpenSearch — Yuhan's LAB"
    version: str = "1.0.0"

    http_timeout: int = 12
    module_timeout: int = 90
    maigret_timeout: int = 15
    sherlock_timeout: int = 12

    maigret_top_sites: int = 80
    enable_auto_pivot: bool = True
    max_pivot_depth: int = 1
    max_concurrent_modules: int = 6
    user_agent: str = "OpenSearch-YuhansLAB/1.0 (+OSINT Anti-Scam Research)"

    db_path: Path = field(init=False)
    reports_dir: Path = field(init=False)
    uploads_dir: Path = field(init=False)

    web_host: str = "127.0.0.1"
    web_port: int = 5000
    max_upload_mb: int = 16

    env_overrides: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.db_path = self.root_dir / "data" / "opensearch.db"
        self.reports_dir = self.root_dir / "reports"
        self.uploads_dir = self.root_dir / "data" / "uploads"

    @classmethod
    def load(
        cls,
        root_dir: Path | str | None = None,
        config_path: Path | str | None = None,
        dotenv_path: Path | str | None = None,
    ) -> AppConfig:
        """Load config from config.yaml and .env relative to workspace root."""
        base_dir = Path(root_dir) if root_dir else Path(__file__).resolve().parents[2]
        cfg_file = Path(config_path) if config_path else base_dir / "config.yaml"
        env_file = Path(dotenv_path) if dotenv_path else base_dir / ".env"

        raw: dict[str, Any] = {}
        if cfg_file.is_file():
            loaded = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                raw = loaded

        app_sec = raw.get("app", {}) or {}
        to_sec = raw.get("timeouts", {}) or {}
        scan_sec = raw.get("scan", {}) or {}
        paths_sec = raw.get("paths", {}) or {}
        web_sec = raw.get("web", {}) or {}

        dotenv_vars = _parse_dotenv(env_file)

        instance = cls(
            root_dir=base_dir,
            app_name=str(app_sec.get("name", "OpenSearch — Yuhan's LAB")),
            version=str(app_sec.get("version", "1.0.0")),
            http_timeout=int(to_sec.get("http_seconds", 12)),
            module_timeout=int(to_sec.get("module_seconds", 90)),
            maigret_timeout=int(to_sec.get("maigret_seconds", 15)),
            sherlock_timeout=int(to_sec.get("sherlock_seconds", 12)),
            maigret_top_sites=int(scan_sec.get("maigret_top_sites", 80)),
            enable_auto_pivot=bool(scan_sec.get("enable_auto_pivot", True)),
            max_pivot_depth=int(scan_sec.get("max_pivot_depth", 1)),
            max_concurrent_modules=int(scan_sec.get("max_concurrent_modules", 6)),
            user_agent=str(scan_sec.get("user_agent", "OpenSearch-YuhansLAB/1.0 (+OSINT Anti-Scam Research)")),
            web_host=str(web_sec.get("host", "127.0.0.1")),
            web_port=int(web_sec.get("port", 5000)),
            max_upload_mb=int(web_sec.get("max_upload_mb", 16)),
            env_overrides=dotenv_vars,
        )

        db_rel = str(paths_sec.get("db_path", "data/opensearch.db"))
        reports_rel = str(paths_sec.get("reports_dir", "reports"))
        uploads_rel = str(paths_sec.get("uploads_dir", "data/uploads"))

        instance.db_path = cls._resolve_path(base_dir, db_rel)
        instance.reports_dir = cls._resolve_path(base_dir, reports_rel)
        instance.uploads_dir = cls._resolve_path(base_dir, uploads_rel)

        return instance

    @staticmethod
    def _resolve_path(base_dir: Path, raw_path: str) -> Path:
        p = Path(raw_path)
        return p if p.is_absolute() else (base_dir / p)

    def ensure_directories(self) -> None:
        """Create required runtime directories if they do not exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.uploads_dir.mkdir(parents=True, exist_ok=True)

    def get_env(self, name: str, default: str | None = None) -> str | None:
        """Retrieve a setting from OS environment first, then .env file."""
        val = os.environ.get(name)
        if val is not None and val.strip() != "":
            return val.strip()
        dot_val = self.env_overrides.get(name)
        if dot_val is not None and dot_val.strip() != "":
            return dot_val.strip()
        return default

    def get_api_key(self, env_name: str) -> str | None:
        """Return configured API key or None if unset."""
        if not env_name:
            return None
        return self.get_env(env_name)

    def api_key_status(self) -> dict[str, bool]:
        """Return availability flags for all known optional OSINT API keys."""
        return {key: bool(self.get_api_key(key)) for key in API_KEY_ENV_VARS}
