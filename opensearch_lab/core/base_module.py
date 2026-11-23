"""Base abstractions for OSINT investigation modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import aiohttp

from opensearch_lab.core.config import AppConfig
from opensearch_lab.core.models import ModuleResult, TargetType

if TYPE_CHECKING:
    from opensearch_lab.core.storage import Storage


@dataclass
class InvestigationContext:
    """Shared runtime context passed to every OSINT module."""

    config: AppConfig
    http_session: aiohttp.ClientSession
    storage: Storage | None = None
    options: dict[str, Any] = field(default_factory=dict)


class BaseOSINTModule(ABC):
    """Abstract base class implemented by all OpenSearch OSINT modules."""

    name: str = "base"
    display_name: str = "Base Module"
    description: str = ""
    category: str = "general"
    supported_targets: set[TargetType] = set()
    requires_api_key: bool = False
    api_key_env: str = ""
    is_slow: bool = False
    default_enabled: bool = True

    def is_available(self, config: AppConfig) -> tuple[bool, str]:
        """Check whether the module can run in the current environment."""
        if self.requires_api_key and self.api_key_env:
            if not config.get_api_key(self.api_key_env):
                return False, f"Missing required API key: {self.api_key_env}"
        return True, "Ready"

    def optional_key_status(self, config: AppConfig) -> str:
        """Human-readable status of any optional/required API key."""
        if not self.api_key_env:
            return "No key needed"
        if config.get_api_key(self.api_key_env):
            return f"{self.api_key_env} configured"
        if self.requires_api_key:
            return f"{self.api_key_env} missing (required)"
        return f"Free mode ({self.api_key_env} optional)"

    @abstractmethod
    async def run(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
    ) -> ModuleResult:
        """Execute investigation against target and return structured ModuleResult."""
        raise NotImplementedError
