"""OSINT module registrations for OpenSearch — Yuhan's LAB."""

from __future__ import annotations

from opensearch_lab.core.registry import ModuleRegistry
from opensearch_lab.modules.bank_intel import BankAccountModule
from opensearch_lab.modules.crypto_intel import CryptoOsintModule
from opensearch_lab.modules.email_intel import EmailOsintModule
from opensearch_lab.modules.image_forensics import ImageForensicsModule
from opensearch_lab.modules.infra_intel import (
    DnsSslCtModule,
    IpReputationModule,
    RdapWhoisModule,
    ShodanModule,
)
from opensearch_lab.modules.person_intel import PersonAliasModule
from opensearch_lab.modules.phone_intel import PhoneOsintModule
from opensearch_lab.modules.scam_intel import ScamDorkModule, UrlPhishingModule
from opensearch_lab.modules.threat_feeds import ThreatFeedsModule
from opensearch_lab.modules.username_intel import (
    MaigretModule,
    PublicProfileFastModule,
    SherlockModule,
)
from opensearch_lab.modules.web_content_intel import WebContentAnalyzerModule


def register_all_modules(registry: ModuleRegistry) -> ModuleRegistry:
    """Register all built-in OSINT and anti-scam modules on the given registry."""
    modules = [
        MaigretModule(),
        SherlockModule(),
        PublicProfileFastModule(),
        ShodanModule(),
        DnsSslCtModule(),
        RdapWhoisModule(),
        IpReputationModule(),
        UrlPhishingModule(),
        WebContentAnalyzerModule(),
        ThreatFeedsModule(),
        ScamDorkModule(),
        EmailOsintModule(),
        PhoneOsintModule(),
        BankAccountModule(),
        CryptoOsintModule(),
        ImageForensicsModule(),
        PersonAliasModule(),
    ]
    for mod in modules:
        registry.register(mod)
    return registry


def create_default_registry() -> ModuleRegistry:
    """Instantiate a ModuleRegistry pre-populated with all built-in modules."""
    return register_all_modules(ModuleRegistry())
