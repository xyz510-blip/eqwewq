"""Module registry for discovering, filtering, and inspecting OSINT modules."""

from __future__ import annotations

from typing import Iterable

from opensearch_lab.core.base_module import BaseOSINTModule
from opensearch_lab.core.config import AppConfig
from opensearch_lab.core.models import TargetType


class ModuleRegistry:
    """Central registry holding all instantiated OSINT modules."""

    def __init__(self) -> None:
        self._modules: dict[str, BaseOSINTModule] = {}

    def register(self, module: BaseOSINTModule) -> None:
        """Register an OSINT module instance by its unique name."""
        self._modules[module.name] = module

    def get(self, name: str) -> BaseOSINTModule | None:
        """Return a module by name, if registered."""
        return self._modules.get(name)

    def all_modules(self) -> list[BaseOSINTModule]:
        """Return all registered modules in registration order."""
        return list(self._modules.values())

    def describe_all(self, config: AppConfig) -> list[dict[str, object]]:
        """Return structured metadata and availability for all modules."""
        items: list[dict[str, object]] = []
        for mod in self._modules.values():
            available, reason = mod.is_available(config)
            items.append(
                {
                    "name": mod.name,
                    "display_name": mod.display_name,
                    "description": mod.description,
                    "category": mod.category,
                    "supported_targets": sorted(t.value for t in mod.supported_targets),
                    "requires_api_key": mod.requires_api_key,
                    "api_key_env": mod.api_key_env,
                    "key_status": mod.optional_key_status(config),
                    "is_slow": mod.is_slow,
                    "default_enabled": mod.default_enabled,
                    "available": available,
                    "status_reason": reason,
                }
            )
        return items

    def select_for_target(
        self,
        target_type: TargetType,
        config: AppConfig,
        include_modules: Iterable[str] | None = None,
        exclude_modules: Iterable[str] | None = None,
        include_slow: bool = True,
    ) -> list[BaseOSINTModule]:
        """Select applicable, available modules for the target type and user filters."""
        include_set = {m.strip().lower() for m in include_modules if m.strip()} if include_modules else None
        exclude_set = {m.strip().lower() for m in exclude_modules if m.strip()} if exclude_modules else set()

        selected: list[BaseOSINTModule] = []
        for mod in self._modules.values():
            if target_type not in mod.supported_targets:
                continue
            if include_set is not None and mod.name.lower() not in include_set:
                continue
            if mod.name.lower() in exclude_set:
                continue
            if not include_slow and mod.is_slow and (include_set is None or mod.name.lower() not in include_set):
                continue
            available, _ = mod.is_available(config)
            if not available:
                continue
            selected.append(mod)
        return selected
