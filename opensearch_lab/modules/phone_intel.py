"""Phone number OSINT module with Indonesian carrier prefixes, E.164 normalization, and scam flags."""

from __future__ import annotations

import re
import time
from urllib.parse import quote

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.correlator import make_entity_id
from opensearch_lab.core.known_entities import OFFICIAL_ID_HOTLINES
from opensearch_lab.core.models import (
    EntityEdge,
    EntityNode,
    Finding,
    ModuleResult,
    Severity,
    TargetType,
)

# Indonesian mobile prefixes (4-digit local prefix starting with 08xx)
ID_CARRIERS: dict[str, str] = {
    "0811": "Telkomsel (Kartu Halo)",
    "0812": "Telkomsel (Simpati / Halo)",
    "0813": "Telkomsel (Simpati)",
    "0821": "Telkomsel (Simpati)",
    "0822": "Telkomsel (Loop)",
    "0823": "Telkomsel (Kartu As)",
    "0851": "Telkomsel / by.U",
    "0852": "Telkomsel (Kartu As)",
    "0853": "Telkomsel (Kartu As)",
    "0814": "Indosat Ooredoo Hutchison (IM3)",
    "0815": "Indosat Ooredoo Hutchison (Matrix/Mentari)",
    "0816": "Indosat Ooredoo Hutchison (Mentari/Matrix)",
    "0855": "Indosat Ooredoo Hutchison (Matrix)",
    "0856": "Indosat Ooredoo Hutchison (IM3)",
    "0857": "Indosat Ooredoo Hutchison (IM3)",
    "0858": "Indosat Ooredoo Hutchison (Mentari)",
    "0895": "Tri / 3 Indonesia (IOH)",
    "0896": "Tri / 3 Indonesia (IOH)",
    "0897": "Tri / 3 Indonesia (IOH)",
    "0898": "Tri / 3 Indonesia (IOH)",
    "0899": "Tri / 3 Indonesia (IOH)",
    "0817": "XL Axiata",
    "0818": "XL Axiata",
    "0819": "XL Axiata",
    "0859": "XL Axiata",
    "0877": "XL Axiata",
    "0878": "XL Axiata",
    "0831": "Axis (XL Axiata)",
    "0832": "Axis (XL Axiata)",
    "0833": "Axis (XL Axiata)",
    "0838": "Axis (XL Axiata)",
    "0881": "Smartfren",
    "0882": "Smartfren",
    "0883": "Smartfren",
    "0884": "Smartfren",
    "0885": "Smartfren",
    "0886": "Smartfren",
    "0887": "Smartfren",
    "0888": "Smartfren",
    "0889": "Smartfren",
}

ID_AREA_CODES: dict[str, str] = {
    "021": "Jabodetabek (Landline)",
    "022": "Bandung & Sekitarnya (Landline)",
    "024": "Semarang & Sekitarnya (Landline)",
    "0274": "Yogyakarta (Landline)",
    "031": "Surabaya & Sekitarnya (Landline)",
    "0361": "Denpasar / Bali (Landline)",
    "061": "Medan (Landline)",
    "0411": "Makassar (Landline)",
    "0711": "Palembang (Landline)",
}

COUNTRY_CODES: dict[str, tuple[str, bool]] = {
    # code: (country_name, elevated_cross_border_scam_note)
    "62": ("Indonesia", False),
    "65": ("Singapura", False),
    "60": ("Malaysia", False),
    "61": ("Australia", False),
    "1": ("Amerika Serikat / Kanada", False),
    "44": ("Inggris (UK)", False),
    "81": ("Jepang", False),
    "82": ("Korea Selatan", False),
    "86": ("Tiongkok", False),
    "91": ("India", False),
    "63": ("Filipina", True),
    "855": ("Kamboja", True),
    "95": ("Myanmar", True),
    "856": ("Laos", True),
    "234": ("Nigeria", True),
    "7": ("Rusia / Kazakhstan", False),
}


class PhoneOsintModule(BaseOSINTModule):
    """Phone number normalization, Indonesian carrier lookup, WhatsApp/Telegram pivots & Numverify."""

    name = "phone_osint"
    display_name = "Phone & WhatsApp Intelligence"
    description = "Normalisasi E.164, deteksi operator Indonesia/negara asal, cek WhatsApp/Telegram, dan Numverify opsional."
    category = "identity_osint"
    supported_targets = {TargetType.PHONE}
    requires_api_key = False
    api_key_env = "NUMVERIFY_API_KEY"

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

        digits = re.sub(r"\D", "", target)

        if digits in OFFICIAL_ID_HOTLINES:
            official_name = OFFICIAL_ID_HOTLINES[digits]
            findings.append(
                Finding(
                    source=self.name,
                    category="trust_signal",
                    title="Hotline Resmi Instansi / Bank Terverifikasi",
                    value=f"{digits} adalah call center resmi: {official_name}.",
                    severity=Severity.INFO,
                    confidence=0.98,
                    risk_delta=0,
                    verification_status="verified",
                    signal_tier="trust",
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
                summary=f"Nomor {digits} adalah hotline resmi ({official_name}).",
            )

        e164, local_id, country_name, carrier, is_elevated_region = self._analyze_number(target, digits)

        if not (8 <= len(digits) <= 15):
            findings.append(
                Finding(
                    source=self.name,
                    category="phone_validation",
                    title="Panjang Nomor Telepon Tidak Standar",
                    value=f"Nomor '{target}' memiliki {len(digits)} digit (standar E.164: 8-15 digit).",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    risk_delta=12,
                    signal_tier="suspicious",
                )
            )
        elif local_id.startswith("08") and not (10 <= len(local_id) <= 13):
            findings.append(
                Finding(
                    source=self.name,
                    category="phone_validation",
                    title="Panjang Nomor Seluler Indonesia Tidak Lazim",
                    value=f"Nomor lokal {local_id} memiliki {len(local_id)} digit (umumnya 10-13 digit).",
                    severity=Severity.LOW,
                    confidence=0.82,
                    risk_delta=8,
                    signal_tier="advisory",
                )
            )

        wa_digits = e164.lstrip("+")
        wa_url = f"https://wa.me/{wa_digits}"
        tg_url = f"https://t.me/{e164}"

        findings.append(
            Finding(
                source=self.name,
                category="phone_metadata",
                title="Normalisasi & Operator Telepon",
                value=f"E.164: {e164} | Lokal: {local_id or '-'} | Negara: {country_name} | Operator/Tipe: {carrier}",
                severity=Severity.INFO,
                confidence=0.95,
                metadata={
                    "e164": e164,
                    "local": local_id,
                    "country": country_name,
                    "carrier": carrier,
                },
            )
        )

        if carrier and carrier != "Tidak diketahui":
            cid = make_entity_id("carrier", carrier)
            entities.append(EntityNode(id=cid, label=carrier, entity_type="organization"))
            edges.append(EntityEdge(source=root_id, target=cid, relation="operated_by"))

        if is_elevated_region:
            findings.append(
                Finding(
                    source=self.name,
                    category="regional_advisory",
                    title="Catatan Nomor Internasional",
                    value=f"Nomor berasal dari {country_name} ({e164}). Verifikasi konteks komunikasi jika tidak mengenal pihak luar negeri.",
                    severity=Severity.INFO,
                    confidence=0.85,
                    risk_delta=0,
                    signal_tier="advisory",
                )
            )

        # Actionable pivot links
        findings.append(
            Finding(
                source=self.name,
                category="messaging_pivot",
                title="Cek Profil WhatsApp Langsung",
                value=f"Buka chat / cek foto profil & status WA untuk {e164}",
                url=wa_url,
                severity=Severity.INFO,
                confidence=1.0,
            )
        )
        findings.append(
            Finding(
                source=self.name,
                category="messaging_pivot",
                title="Cek Akun Telegram via Nomor",
                value=f"Cek apakah {e164} terhubung ke akun Telegram publik",
                url=tg_url,
                severity=Severity.INFO,
                confidence=1.0,
            )
        )
        findings.append(
            Finding(
                source=self.name,
                category="investigation_link",
                title="Cek Nomor di Truecaller Web",
                value=f"Cari identitas penelepon/label spam untuk {e164}",
                url=f"https://www.truecaller.com/search/{'id' if country_name == 'Indonesia' else 'us'}/{quote(local_id or wa_digits)}",
                severity=Severity.INFO,
                confidence=0.9,
            )
        )

        # Optional Numverify API
        nv_key = ctx.config.get_api_key("NUMVERIFY_API_KEY")
        if nv_key:
            try:
                nv_url = f"http://apilayer.net/api/validate?access_key={quote(nv_key)}&number={quote(wa_digits)}"
                async with ctx.http_session.get(nv_url, timeout=8) as resp:
                    if resp.status == 200:
                        nv = await resp.json()
                        if nv.get("valid"):
                            line_type = str(nv.get("line_type") or "-")
                            nv_carrier = str(nv.get("carrier") or "-")
                            is_voip = line_type.lower() == "voip"
                            findings.append(
                                Finding(
                                    source=self.name,
                                    category="phone_verification",
                                    title="Validasi Numverify API",
                                    value=f"Valid: {nv.get('valid')} | Line Type: {line_type} | Carrier: {nv_carrier} | Lokasi: {nv.get('location', '-')}",
                                    severity=Severity.MEDIUM if is_voip else Severity.INFO,
                                    confidence=0.95,
                                    risk_delta=15 if is_voip else 0,
                                    metadata=nv,
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
            summary=f"Nomor {e164} teridentifikasi ({country_name} / {carrier}).",
        )

    @staticmethod
    def _analyze_number(raw: str, digits: str) -> tuple[str, str, str, str, bool]:
        local_id = ""
        e164 = f"+{digits}"
        country_name = "Tidak diketahui"
        carrier = "Tidak diketahui"
        elevated = False

        if raw.strip().startswith("0") or digits.startswith("62") or (digits.startswith("8") and 9 <= len(digits) <= 12):
            if digits.startswith("62"):
                local_id = "0" + digits[2:]
                e164 = f"+{digits}"
            elif digits.startswith("8"):
                local_id = "0" + digits
                e164 = f"+62{digits}"
            else:
                local_id = digits
                e164 = f"+62{digits[1:]}"
            country_name = "Indonesia"
            if len(local_id) >= 4 and local_id[:4] in ID_CARRIERS:
                carrier = ID_CARRIERS[local_id[:4]]
            elif len(local_id) >= 4 and local_id[:4] in ID_AREA_CODES:
                carrier = ID_AREA_CODES[local_id[:4]]
            elif len(local_id) >= 3 and local_id[:3] in ID_AREA_CODES:
                carrier = ID_AREA_CODES[local_id[:3]]
            elif local_id.startswith("08"):
                carrier = "Seluler Indonesia (Prefix khusus/baru)"
        else:
            # Match longest country calling code first
            for cc in sorted(COUNTRY_CODES.keys(), key=len, reverse=True):
                if digits.startswith(cc):
                    country_name, elevated = COUNTRY_CODES[cc]
                    carrier = f"International (+{cc})"
                    break

        return e164, local_id, country_name, carrier, elevated
