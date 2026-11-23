"""Infrastructure OSINT modules: Shodan (InternetDB + API), DNS/SSL/CT, RDAP/WHOIS, IP Reputation."""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.correlator import make_entity_id
from opensearch_lab.core.domain_utils import extract_registrable_domain
from opensearch_lab.core.known_entities import SHARED_CDN_HOSTING_KEYWORDS
from opensearch_lab.core.models import (
    EntityEdge,
    EntityNode,
    Finding,
    ModuleResult,
    Severity,
    TargetType,
)

# Remote-admin / raw database ports (exclude normal web, mail, SSH, and cPanel ports)
RISKY_PORTS = {23, 445, 1433, 3389, 5900, 6379, 27017}
CPANEL_SHARED_PORTS = {2077, 2082, 2083, 2086, 2087, 2095, 2096}
RISKY_SHODAN_TAGS = {"compromised", "malware", "phishing", "botnet"}


def _extract_domain(target: str, target_type: TargetType) -> str:
    if target_type == TargetType.URL:
        return (urlparse(target).hostname or target).lower().rstrip(".")
    return target.lower().rstrip(".")


def _parse_iso_dt(value: str) -> datetime | None:
    if not value:
        return None
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


class ShodanModule(BaseOSINTModule):
    """Shodan InternetDB (free, no key) + optional Shodan Host API enrichment."""

    name = "shodan"
    display_name = "Shodan Infrastructure & Port Intel"
    description = "Memetakan port terbuka, CPE, kerentanan CVE, tags ancaman, dan banner layanan via Shodan."
    category = "infrastructure"
    supported_targets = {TargetType.IP, TargetType.DOMAIN}
    requires_api_key = False
    api_key_env = "SHODAN_API_KEY"

    async def run(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
    ) -> ModuleResult:
        started = time.perf_counter()
        findings: list[Finding] = []
        entities: list[EntityNode] = []
        edges: list[EntityEdge] = []
        pivots: list[dict[str, str]] = []
        root_id = make_entity_id(target_type.value, target)

        ip_addr = target
        if target_type == TargetType.DOMAIN:
            try:
                ip_addr = await asyncio.to_thread(socket.gethostbyname, target)
                ip_node_id = make_entity_id("ip", ip_addr)
                entities.append(EntityNode(id=ip_node_id, label=ip_addr, entity_type="ip"))
                edges.append(EntityEdge(source=root_id, target=ip_node_id, relation="resolves_to"))
                pivots.append({"value": ip_addr, "type": "ip", "reason": f"IP hasil resolusi dari {target}"})
            except Exception as exc:
                elapsed = int((time.perf_counter() - started) * 1000)
                return ModuleResult(
                    module_name=self.name,
                    display_name=self.display_name,
                    status="partial",
                    duration_ms=elapsed,
                    summary=f"Tidak dapat me-resolve domain {target} ke IP.",
                    error=str(exc),
                )

        ip_entity_id = make_entity_id("ip", ip_addr)

        # 1. Free Shodan InternetDB
        idb_url = f"https://internetdb.shodan.io/{ip_addr}"
        try:
            async with ctx.http_session.get(idb_url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ports = data.get("ports") or []
                    hostnames = data.get("hostnames") or []
                    cpes = data.get("cpes") or []
                    vulns = data.get("vulns") or []
                    tags = data.get("tags") or []

                    is_shared_or_cdn = bool(
                        any(p in CPANEL_SHARED_PORTS for p in ports)
                        or any(
                            any(kw in str(hn).lower() for kw in SHARED_CDN_HOSTING_KEYWORDS)
                            for hn in hostnames
                        )
                        or any(
                            any(kw in str(c).lower() for kw in ("cloudflare", "litespeed", "cpanel"))
                            for c in cpes
                        )
                    )

                    if ports:
                        risky_open = [p for p in ports if p in RISKY_PORTS]
                        if is_shared_or_cdn:
                            sev = Severity.INFO
                            delta = 0
                            port_title = "Port Terbuka — Shared Hosting / CDN (Shodan)"
                        else:
                            sev = Severity.MEDIUM if risky_open else Severity.INFO
                            delta = 10 if risky_open else 0
                            port_title = "Port Terbuka (Shodan InternetDB)"
                        findings.append(
                            Finding(
                                source=self.name,
                                category="shodan_ports",
                                title=port_title,
                                value=", ".join(str(p) for p in ports),
                                url=f"https://www.shodan.io/host/{ip_addr}",
                                severity=sev,
                                confidence=0.95,
                                risk_delta=delta,
                                signal_tier="advisory",
                                metadata={
                                    "ports": ports,
                                    "risky_ports": risky_open,
                                    "shared_hosting_or_cdn": is_shared_or_cdn,
                                },
                            )
                        )
                        for p in ports[:15]:
                            p_id = make_entity_id("port", f"{ip_addr}:{p}")
                            entities.append(EntityNode(id=p_id, label=f"Port {p}", entity_type="port"))
                            edges.append(EntityEdge(source=ip_entity_id, target=p_id, relation="exposes_port"))

                    if hostnames:
                        findings.append(
                            Finding(
                                source=self.name,
                                category="shodan_hostnames",
                                title="Reverse Hostnames (Shodan)",
                                value=", ".join(hostnames[:10]),
                                url=f"https://www.shodan.io/host/{ip_addr}",
                                severity=Severity.INFO,
                                confidence=0.9,
                            )
                        )
                        if not is_shared_or_cdn:
                            for hn in hostnames[:5]:
                                pivots.append({"value": hn, "type": "domain", "reason": "Hostname terhubung di Shodan"})

                    if tags:
                        bad_tags = [t for t in tags if str(t).lower() in RISKY_SHODAN_TAGS]
                        findings.append(
                            Finding(
                                source=self.name,
                                category="shodan_tags",
                                title="Tags Infrastruktur Shodan",
                                value=", ".join(tags),
                                url=f"https://www.shodan.io/host/{ip_addr}",
                                severity=Severity.HIGH if bad_tags else Severity.INFO,
                                confidence=0.9,
                                risk_delta=25 if bad_tags else 0,
                                signal_tier="confirmed_threat" if bad_tags else "info",
                            )
                        )

                    if vulns:
                        findings.append(
                            Finding(
                                source=self.name,
                                category="shodan_vulns",
                                title=f"Terdeteksi {len(vulns)} Kerentanan CVE",
                                value=", ".join(vulns[:12]),
                                url=f"https://www.shodan.io/host/{ip_addr}",
                                severity=Severity.INFO if is_shared_or_cdn else Severity.MEDIUM,
                                confidence=0.88,
                                risk_delta=0 if is_shared_or_cdn else 10,
                                signal_tier="advisory",
                                metadata={"cves": vulns},
                            )
                        )
                        for cve in vulns[:6]:
                            c_id = make_entity_id("cve", cve)
                            entities.append(EntityNode(id=c_id, label=cve, entity_type="cve"))
                            edges.append(EntityEdge(source=ip_entity_id, target=c_id, relation="vulnerable_to"))

                    if cpes:
                        findings.append(
                            Finding(
                                source=self.name,
                                category="shodan_tech",
                                title="Fingerprint Software / CPE",
                                value=", ".join(cpes[:8]),
                                url=f"https://www.shodan.io/host/{ip_addr}",
                                severity=Severity.INFO,
                                confidence=0.85,
                            )
                        )
        except Exception as exc:
            findings.append(
                Finding(
                    source=self.name,
                    category="shodan_status",
                    title="Shodan InternetDB tidak merespons",
                    value=str(exc),
                    severity=Severity.INFO,
                    confidence=0.5,
                )
            )

        # 2. Optional full Shodan API
        api_key = ctx.config.get_api_key("SHODAN_API_KEY")
        if api_key:
            full_url = f"https://api.shodan.io/shodan/host/{ip_addr}?key={quote(api_key)}"
            try:
                async with ctx.http_session.get(full_url) as resp:
                    if resp.status == 200:
                        sdata = await resp.json()
                        org = sdata.get("org") or "-"
                        isp = sdata.get("isp") or "-"
                        asn = sdata.get("asn") or "-"
                        country = sdata.get("country_name") or "-"
                        city = sdata.get("city") or "-"
                        findings.append(
                            Finding(
                                source=self.name,
                                category="shodan_org",
                                title="Detail Organisasi & ASN (Shodan API)",
                                value=f"Org: {org} | ISP: {isp} | ASN: {asn} | Lokasi: {city}, {country}",
                                url=f"https://www.shodan.io/host/{ip_addr}",
                                severity=Severity.INFO,
                                confidence=0.98,
                                metadata={"org": org, "isp": isp, "asn": asn, "country": country, "city": city},
                            )
                        )
            except Exception:
                pass

        elapsed = int((time.perf_counter() - started) * 1000)
        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            status="ok",
            duration_ms=elapsed,
            findings=findings,
            entities=entities,
            edges=edges,
            summary=f"Shodan memindai IP {ip_addr} dengan {len(findings)} temuan.",
            pivot_candidates=pivots,
        )


class DnsSslCtModule(BaseOSINTModule):
    """DNS over HTTPS (A/AAAA/MX/TXT/SPF/DMARC), TLS Certificate Inspection, and CT Subdomains."""

    name = "dns_ssl"
    display_name = "DNS, TLS & Certificate Transparency"
    description = "Memeriksa record DNS, SPF/DMARC anti-spoofing, sertifikat SSL, dan subdomain via crt.sh."
    category = "infrastructure"
    supported_targets = {TargetType.DOMAIN, TargetType.URL}

    async def run(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
    ) -> ModuleResult:
        started = time.perf_counter()
        domain = _extract_domain(target, target_type)
        findings: list[Finding] = []
        entities: list[EntityNode] = []
        edges: list[EntityEdge] = []
        pivots: list[dict[str, str]] = []
        root_id = make_entity_id(target_type.value, target)
        dom_id = make_entity_id("domain", domain)
        if target_type == TargetType.URL:
            entities.append(EntityNode(id=dom_id, label=domain, entity_type="domain"))
            edges.append(EntityEdge(source=root_id, target=dom_id, relation="hosted_on"))

        # Run DoH queries, TLS inspection, and crt.sh concurrently
        dns_task = self._query_dns(domain, dom_id, ctx, findings, entities, edges, pivots)
        tls_task = asyncio.to_thread(self._inspect_tls, domain)
        ct_task = self._query_crtsh(domain, dom_id, ctx, findings, entities, edges, pivots)

        _, tls_res, _ = await asyncio.gather(dns_task, tls_task, ct_task, return_exceptions=True)

        if isinstance(tls_res, dict) and tls_res:
            issuer = tls_res.get("issuer", "-")
            subject = tls_res.get("subject", "-")
            not_before = tls_res.get("not_before_iso") or tls_res.get("not_before", "")
            not_after = tls_res.get("not_after_iso") or tls_res.get("not_after", "")
            sans = tls_res.get("sans", [])
            org_name = tls_res.get("organization", "")
            findings.append(
                Finding(
                    source=self.name,
                    category="ssl_cert",
                    title="Informasi Sertifikat TLS/SSL",
                    value=f"Subject: {subject} | Issuer: {issuer} | Valid: {not_before[:10]} s/d {not_after[:10]}",
                    severity=Severity.INFO,
                    confidence=0.95,
                    metadata=tls_res,
                )
            )
            if org_name and not tls_res.get("self_signed"):
                findings.append(
                    Finding(
                        source=self.name,
                        category="trust_signal",
                        title="Sertifikat SSL Organisasi Terverifikasi (OV/EV)",
                        value=f"Sertifikat TLS diterbitkan resmi untuk badan hukum: {org_name}",
                        severity=Severity.INFO,
                        confidence=0.96,
                        risk_delta=0,
                        verification_status="verified",
                        signal_tier="trust",
                    )
                )
            if tls_res.get("self_signed"):
                findings.append(
                    Finding(
                        source=self.name,
                        category="ssl_cert",
                        title="Sertifikat SSL Self-Signed",
                        value="Sertifikat diterbitkan sendiri (bukan CA tepercaya)",
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        risk_delta=15,
                        signal_tier="suspicious",
                    )
                )
            elif tls_res.get("age_days") is not None and tls_res["age_days"] <= 14:
                findings.append(
                    Finding(
                        source=self.name,
                        category="ssl_cert",
                        title="Sertifikat SSL Baru Diperbarui/Diterbitkan (<=14 hari)",
                        value=f"Usia sertifikat TLS {tls_res['age_days']} hari (normal untuk auto-renewal Let's Encrypt).",
                        severity=Severity.INFO,
                        confidence=0.9,
                        risk_delta=0,
                    )
                )
            for san in sans[:5]:
                clean_san = san.lstrip("*.")
                if clean_san and clean_san != domain:
                    pivots.append({"value": clean_san, "type": "domain", "reason": "SAN pada sertifikat TLS"})

        elapsed = int((time.perf_counter() - started) * 1000)
        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            status="ok",
            duration_ms=elapsed,
            findings=findings,
            entities=entities,
            edges=edges,
            summary=f"Analisis DNS/TLS/CT untuk {domain} selesai ({len(findings)} temuan).",
            pivot_candidates=pivots,
        )

    async def _doh_lookup(self, ctx: InvestigationContext, name: str, rtype: str) -> list[str]:
        url = f"https://cloudflare-dns.com/dns-query?name={quote(name)}&type={rtype}"
        try:
            async with ctx.http_session.get(url, headers={"Accept": "application/dns-json"}) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json(content_type=None)
                answers = data.get("Answer") or []
                return [str(a.get("data", "")).strip('" ') for a in answers if a.get("data")]
        except Exception:
            return []

    async def _query_dns(
        self,
        domain: str,
        dom_id: str,
        ctx: InvestigationContext,
        findings: list[Finding],
        entities: list[EntityNode],
        edges: list[EntityEdge],
        pivots: list[dict[str, str]],
    ) -> None:
        apex = extract_registrable_domain(domain) or domain
        a_recs, mx_recs, txt_recs, ns_recs, dmarc_recs = await asyncio.gather(
            self._doh_lookup(ctx, domain, "A"),
            self._doh_lookup(ctx, apex, "MX"),
            self._doh_lookup(ctx, apex, "TXT"),
            self._doh_lookup(ctx, apex, "NS"),
            self._doh_lookup(ctx, f"_dmarc.{apex}", "TXT"),
        )
        if a_recs:
            findings.append(
                Finding(
                    source=self.name,
                    category="dns",
                    title="DNS A Record",
                    value=", ".join(a_recs),
                    severity=Severity.INFO,
                    confidence=0.95,
                )
            )
            for ip in a_recs[:4]:
                ip_id = make_entity_id("ip", ip)
                entities.append(EntityNode(id=ip_id, label=ip, entity_type="ip"))
                edges.append(EntityEdge(source=dom_id, target=ip_id, relation="resolves_to"))
                pivots.append({"value": ip, "type": "ip", "reason": f"DNS A record untuk {domain}"})

        if mx_recs:
            findings.append(
                Finding(
                    source=self.name,
                    category="dns",
                    title="DNS MX Record",
                    value=", ".join(mx_recs[:6]),
                    severity=Severity.INFO,
                    confidence=0.95,
                )
            )
        if ns_recs:
            findings.append(
                Finding(
                    source=self.name,
                    category="dns",
                    title="Nameservers (NS)",
                    value=", ".join(ns_recs[:6]),
                    severity=Severity.INFO,
                    confidence=0.95,
                )
            )

        has_spf = any("v=spf1" in t.lower() for t in txt_recs)
        has_dmarc = any("v=dmarc1" in d.lower() for d in dmarc_recs)
        if not has_spf or not has_dmarc:
            missing = []
            if not has_spf:
                missing.append("SPF")
            if not has_dmarc:
                missing.append("DMARC")
            findings.append(
                Finding(
                    source=self.name,
                    category="email_security",
                    title=f"Catatan Keamanan Email ({', '.join(missing)} belum terpasang pada {apex})",
                    value="Informasi postur keamanan email domain (tidak menandakan penipuan secara langsung).",
                    severity=Severity.INFO,
                    confidence=0.9,
                    risk_delta=0,
                    signal_tier="advisory",
                )
            )

    @staticmethod
    def _inspect_tls(domain: str) -> dict[str, Any]:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        if not cert:
            return {}
        subject_dict = {k: v for tup in cert.get("subject", ()) for k, v in tup}
        subject_parts = [f"{k}={v}" for k, v in subject_dict.items()]
        issuer_parts = [f"{k}={v}" for tup in cert.get("issuer", ()) for k, v in tup]
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        nb_str = cert.get("notBefore", "")
        na_str = cert.get("notAfter", "")
        nb_iso = ""
        na_iso = ""
        age_days = None
        try:
            nb_dt = datetime.strptime(nb_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            nb_iso = nb_dt.date().isoformat()
            age_days = (datetime.now(timezone.utc) - nb_dt).days
        except Exception:
            pass
        try:
            na_dt = datetime.strptime(na_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            na_iso = na_dt.date().isoformat()
        except Exception:
            pass
        subject_s = ", ".join(subject_parts)
        issuer_s = ", ".join(issuer_parts)
        return {
            "subject": subject_s,
            "issuer": issuer_s,
            "organization": subject_dict.get("organizationName", ""),
            "not_before": nb_str,
            "not_after": na_str,
            "not_before_iso": nb_iso,
            "not_after_iso": na_iso,
            "sans": sans,
            "age_days": age_days,
            "self_signed": bool(subject_s and subject_s == issuer_s),
        }

    async def _query_crtsh(
        self,
        domain: str,
        dom_id: str,
        ctx: InvestigationContext,
        findings: list[Finding],
        entities: list[EntityNode],
        edges: list[EntityEdge],
        pivots: list[dict[str, str]],
    ) -> None:
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        try:
            async with ctx.http_session.get(url, timeout=8) as resp:
                if resp.status != 200:
                    return
                data = await resp.json(content_type=None)
        except Exception:
            return
        if not isinstance(data, list):
            return
        subdomains: set[str] = set()
        for row in data[:120]:
            name_val = str(row.get("name_value") or "")
            for item in name_val.splitlines():
                clean = item.strip().lower().lstrip("*.")
                if clean and clean.endswith(domain) and clean != domain and " " not in clean:
                    subdomains.add(clean)
        if subdomains:
            sorted_subs = sorted(subdomains)[:25]
            findings.append(
                Finding(
                    source=self.name,
                    category="subdomains",
                    title=f"Subdomain dari Certificate Transparency ({len(subdomains)} ditemukan)",
                    value=", ".join(sorted_subs[:12]),
                    url=f"https://crt.sh/?q=%25.{quote(domain)}",
                    severity=Severity.INFO,
                    confidence=0.9,
                    metadata={"subdomains": sorted_subs},
                )
            )
            for sub in sorted_subs[:5]:
                sid = make_entity_id("domain", sub)
                entities.append(EntityNode(id=sid, label=sub, entity_type="domain"))
                edges.append(EntityEdge(source=dom_id, target=sid, relation="has_subdomain"))
                pivots.append({"value": sub, "type": "domain", "reason": "Subdomain dari CT log crt.sh"})


class RdapWhoisModule(BaseOSINTModule):
    """RDAP/WHOIS registrar, registration date, and domain age scam detector."""

    name = "rdap_whois"
    display_name = "RDAP / WHOIS & Domain Age"
    description = "Memeriksa registrar, tanggal pendaftaran, kontak abuse, dan mendeteksi domain baru (rawan scam)."
    category = "infrastructure"
    supported_targets = {TargetType.DOMAIN, TargetType.IP}

    async def run(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
    ) -> ModuleResult:
        started = time.perf_counter()
        findings: list[Finding] = []
        entities: list[EntityNode] = []
        edges: list[EntityEdge] = []
        root_id = make_entity_id(target_type.value, target)

        query_target = target if target_type == TargetType.IP else (extract_registrable_domain(target) or target)
        endpoint = (
            f"https://rdap.org/ip/{quote(query_target)}"
            if target_type == TargetType.IP
            else f"https://rdap.org/domain/{quote(query_target)}"
        )

        try:
            async with ctx.http_session.get(endpoint) as resp:
                if resp.status != 200:
                    elapsed = int((time.perf_counter() - started) * 1000)
                    return ModuleResult(
                        module_name=self.name,
                        display_name=self.display_name,
                        status="partial",
                        duration_ms=elapsed,
                        summary=f"RDAP merespons HTTP {resp.status} untuk {target}.",
                    )
                data = await resp.json(content_type=None)
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                status="error",
                duration_ms=elapsed,
                error=str(exc),
            )

        events = data.get("events") or []
        reg_date = None
        exp_date = None
        for ev in events:
            action = str(ev.get("eventAction") or "").lower()
            dt = _parse_iso_dt(str(ev.get("eventDate") or ""))
            if action == "registration" and dt:
                reg_date = dt
            elif action == "expiration" and dt:
                exp_date = dt

        registrar = ""
        abuse_emails: list[str] = []
        for ent in data.get("entities") or []:
            roles = [str(r).lower() for r in (ent.get("roles") or [])]
            vcard = (ent.get("vcardArray") or [None, []])[1]
            fn = ""
            for field in vcard if isinstance(vcard, list) else []:
                if isinstance(field, list) and len(field) >= 4:
                    if field[0] == "fn":
                        fn = str(field[3])
                    elif field[0] == "email":
                        abuse_emails.append(str(field[3]))
            if "registrar" in roles and fn:
                registrar = fn

        nameservers = [
            str(ns.get("ldhName") or "").lower()
            for ns in (data.get("nameservers") or [])
            if isinstance(ns, dict) and ns.get("ldhName")
        ]
        summary_parts = []
        if registrar:
            summary_parts.append(f"Registrar: {registrar}")
        if reg_date:
            summary_parts.append(f"Registered: {reg_date.date().isoformat()}")
        if exp_date:
            summary_parts.append(f"Expires: {exp_date.date().isoformat()}")
        if data.get("name"):
            summary_parts.append(f"NetName: {data.get('name')}")

        findings.append(
            Finding(
                source=self.name,
                category="whois",
                title="Data Registrasi RDAP / WHOIS",
                value=" | ".join(summary_parts) or "Data RDAP tersedia",
                url=endpoint,
                severity=Severity.INFO,
                confidence=0.95,
                metadata={
                    "registrar": registrar,
                    "nameservers": nameservers,
                    "abuse_emails": abuse_emails,
                    "status": data.get("status") or [],
                },
            )
        )

        if registrar:
            reg_id = make_entity_id("organization", registrar)
            entities.append(EntityNode(id=reg_id, label=registrar, entity_type="organization"))
            edges.append(EntityEdge(source=root_id, target=reg_id, relation="registered_via"))

        # Domain age check (scam indicator vs established domain trust)
        if target_type == TargetType.DOMAIN and reg_date is not None:
            age_days = (datetime.now(timezone.utc) - reg_date).days
            if age_days < 30:
                findings.append(
                    Finding(
                        source=self.name,
                        category="scam_indicator",
                        title="Domain Sangat Baru (< 30 hari)",
                        value=f"Usia domain hanya {age_days} hari (dibuat {reg_date.date().isoformat()}) — indikator kuat domain penipuan/phishing sekali pakai.",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        risk_delta=30,
                        signal_tier="suspicious",
                        metadata={"domain_age_days": age_days},
                    )
                )
            elif age_days < 90:
                findings.append(
                    Finding(
                        source=self.name,
                        category="scam_indicator",
                        title="Domain Relatif Baru (< 90 hari)",
                        value=f"Usia domain {age_days} hari (dibuat {reg_date.date().isoformat()}).",
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        risk_delta=15,
                        signal_tier="suspicious",
                        metadata={"domain_age_days": age_days},
                    )
                )
            elif age_days >= 730:
                years = age_days // 365
                findings.append(
                    Finding(
                        source=self.name,
                        category="trust_signal",
                        title=f"Domain Mapan (>= {years} tahun)",
                        value=f"Domain {query_target} sudah terdaftar sejak {reg_date.date().isoformat()} ({age_days} hari).",
                        severity=Severity.INFO,
                        confidence=0.95,
                        risk_delta=0,
                        verification_status="verified",
                        signal_tier="trust",
                        metadata={"domain_age_days": age_days},
                    )
                )

        elapsed = int((time.perf_counter() - started) * 1000)
        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            status="ok",
            duration_ms=elapsed,
            findings=findings,
            entities=entities,
            edges=edges,
            summary=f"RDAP lookup selesai untuk {target}.",
        )


class IpReputationModule(BaseOSINTModule):
    """IP geolocation, proxy/hosting detection, and optional AbuseIPDB reputation."""

    name = "ip_reputation"
    display_name = "IP Geolocation & Abuse Reputation"
    description = "Melacak negara/ISP, mendeteksi VPN/Proxy/Hosting, dan mengecek skor abuse AbuseIPDB."
    category = "infrastructure"
    supported_targets = {TargetType.IP}
    requires_api_key = False
    api_key_env = "ABUSEIPDB_API_KEY"

    async def run(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
    ) -> ModuleResult:
        started = time.perf_counter()
        findings: list[Finding] = []
        entities: list[EntityNode] = []
        edges: list[EntityEdge] = []
        root_id = make_entity_id(target_type.value, target)

        # 1. Free ip-api.com lookup
        geo_url = (
            f"http://ip-api.com/json/{quote(target)}"
            "?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,mobile,query"
        )
        try:
            async with ctx.http_session.get(geo_url) as resp:
                if resp.status == 200:
                    g = await resp.json()
                    if g.get("status") == "success":
                        loc = f"{g.get('city', '-')}, {g.get('regionName', '-')}, {g.get('country', '-')}"
                        isp = g.get("isp") or "-"
                        org = g.get("org") or "-"
                        asn = g.get("as") or "-"
                        findings.append(
                            Finding(
                                source=self.name,
                                category="geolocation",
                                title="Geolokasi & ISP IP",
                                value=f"{loc} | ISP: {isp} | Org: {org} | {asn}",
                                severity=Severity.INFO,
                                confidence=0.92,
                                metadata=g,
                            )
                        )
                        if org and org != "-":
                            oid = make_entity_id("organization", org)
                            entities.append(EntityNode(id=oid, label=org, entity_type="organization"))
                            edges.append(EntityEdge(source=root_id, target=oid, relation="operated_by"))
                        if g.get("proxy"):
                            findings.append(
                                Finding(
                                    source=self.name,
                                    category="anonymizer",
                                    title="IP Terdeteksi sebagai VPN / Proxy / Tor",
                                    value=f"{target} ditandai sebagai node proxy/VPN/anonymizer.",
                                    severity=Severity.MEDIUM,
                                    confidence=0.85,
                                    risk_delta=10,
                                    signal_tier="advisory",
                                )
                            )
                        elif g.get("hosting"):
                            findings.append(
                                Finding(
                                    source=self.name,
                                    category="hosting",
                                    title="IP Datacenter / Cloud Hosting",
                                    value=f"{target} berasal dari infrastruktur datacenter ({isp}).",
                                    severity=Severity.INFO,
                                    confidence=0.9,
                                )
                            )
        except Exception:
            pass

        # 2. Optional IPinfo
        ipinfo_token = ctx.config.get_api_key("IPINFO_TOKEN")
        if ipinfo_token:
            try:
                async with ctx.http_session.get(
                    f"https://ipinfo.io/{quote(target)}/json?token={quote(ipinfo_token)}"
                ) as resp:
                    if resp.status == 200:
                        idata = await resp.json()
                        findings.append(
                            Finding(
                                source=self.name,
                                category="geolocation",
                                title="IPinfo Enrichment",
                                value=f"Hostname: {idata.get('hostname', '-')} | Org: {idata.get('org', '-')} | Timezone: {idata.get('timezone', '-')}",
                                severity=Severity.INFO,
                                confidence=0.95,
                                metadata=idata,
                            )
                        )
            except Exception:
                pass

        # 3. Optional AbuseIPDB
        abuse_key = ctx.config.get_api_key("ABUSEIPDB_API_KEY")
        if abuse_key:
            try:
                async with ctx.http_session.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": target, "maxAgeInDays": "90"},
                    headers={"Key": abuse_key, "Accept": "application/json"},
                ) as resp:
                    if resp.status == 200:
                        adata = (await resp.json()).get("data") or {}
                        conf_score = int(adata.get("abuseConfidenceScore", 0))
                        total_rep = int(adata.get("totalReports", 0))
                        sev = Severity.INFO
                        delta = 0
                        if conf_score >= 60:
                            sev = Severity.HIGH
                            delta = 30
                        elif conf_score >= 25:
                            sev = Severity.MEDIUM
                            delta = 15
                        findings.append(
                            Finding(
                                source=self.name,
                                category="threat_reputation",
                                title="Skor Reputasi AbuseIPDB",
                                value=f"Abuse Confidence: {conf_score}% ({total_rep} laporan dalam 90 hari)",
                                url=f"https://www.abuseipdb.com/check/{target}",
                                severity=sev,
                                confidence=0.95,
                                risk_delta=delta,
                                signal_tier="confirmed_threat" if conf_score >= 60 else ("suspicious" if conf_score >= 25 else "info"),
                                metadata=adata,
                            )
                        )
            except Exception:
                pass

        elapsed = int((time.perf_counter() - started) * 1000)
        return ModuleResult(
            module_name=self.name,
            display_name=self.display_name,
            status="ok",
            duration_ms=elapsed,
            findings=findings,
            entities=entities,
            edges=edges,
            summary=f"Analisis reputasi & geolokasi IP {target} selesai ({len(findings)} temuan).",
        )
