"""Indonesian bank account & e-wallet verification and anti-scam lookup module."""

from __future__ import annotations

import re
import time
from urllib.parse import quote

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.correlator import make_entity_id
from opensearch_lab.core.models import (
    EntityEdge,
    EntityNode,
    Finding,
    ModuleResult,
    Severity,
    TargetType,
)

# Expected Indonesian account number digit lengths
BANK_DIGIT_RULES: dict[str, tuple[str, tuple[int, ...]]] = {
    "BCA": ("Bank Central Asia (BCA)", (10,)),
    "BRI": ("Bank Rakyat Indonesia (BRI)", (15,)),
    "MANDIRI": ("Bank Mandiri", (13,)),
    "BNI": ("Bank Negara Indonesia (BNI)", (10,)),
    "BSI": ("Bank Syariah Indonesia (BSI)", (10,)),
    "SEABANK": ("SeaBank Indonesia", (12,)),
    "JAGO": ("Bank Jago", (12,)),
    "CIMB": ("CIMB Niaga", (12, 13)),
    "CIMBNIAGA": ("CIMB Niaga", (12, 13)),
    "PERMATA": ("Bank Permata", (10,)),
    "DANAMON": ("Bank Danamon", (10,)),
    "BTN": ("Bank Tabungan Negara (BTN)", (10, 16)),
    "OCBC": ("OCBC Indonesia", (12,)),
    "DANA": ("E-Wallet DANA", (10, 11, 12, 13)),
    "OVO": ("E-Wallet OVO", (10, 11, 12, 13)),
    "GOPAY": ("E-Wallet GoPay", (10, 11, 12, 13)),
    "SHOPEEPAY": ("E-Wallet ShopeePay", (10, 11, 12, 13)),
    "BANK": ("Rekening Bank", (10, 11, 12, 13, 14, 15, 16)),
}


class BankAccountModule(BaseOSINTModule):
    """Validates Indonesian bank account formats and builds fraud-report lookup pivots."""

    name = "bank_account"
    display_name = "Bank Account & CekRekening OSINT"
    description = "Validasi panjang digit rekening bank Indonesia (BCA/BRI/Mandiri/BNI/BSI/SeaBank/Jago) dan pivot ke CekRekening & Kredibel."
    category = "financial_osint"
    supported_targets = {TargetType.BANK_ACCOUNT}

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

        bank_code, digits = self._parse_bank_target(target)
        bank_name, allowed_lens = BANK_DIGIT_RULES.get(
            bank_code, (bank_code or "Rekening Bank", (10, 11, 12, 13, 14, 15, 16))
        )

        is_valid_len = len(digits) in allowed_lens
        findings.append(
            Finding(
                source=self.name,
                category="bank_validation",
                title="Validasi Format Rekening Indonesia",
                value=(
                    f"Bank/Dompet: {bank_name} | No. Rekening: {digits} ({len(digits)} digit) | "
                    f"Format Panjang: {'Sesuai standar' if is_valid_len else f'Tidak lazim (standar {allowed_lens} digit)'}"
                ),
                severity=Severity.INFO if is_valid_len else Severity.LOW,
                confidence=0.95,
                risk_delta=0 if is_valid_len else 5,
                signal_tier="advisory",
                metadata={
                    "bank_code": bank_code,
                    "bank_name": bank_name,
                    "account_number": digits,
                    "valid_length": is_valid_len,
                },
            )
        )

        if bank_code and bank_code != "BANK":
            bid = make_entity_id("organization", bank_name)
            entities.append(EntityNode(id=bid, label=bank_name, entity_type="organization"))
            edges.append(EntityEdge(source=root_id, target=bid, relation="issued_by"))

        # E-wallets or VA prefixes often mirror phone numbers (08xx...)
        if digits.startswith("08") and 10 <= len(digits) <= 13:
            pivots.append(
                {
                    "value": digits,
                    "type": "phone",
                    "reason": f"Nomor rekening/e-wallet {bank_name} juga merupakan nomor HP Indonesia",
                }
            )
        elif bank_code in {"DANA", "OVO", "GOPAY", "SHOPEEPAY"} and digits.startswith("8") and 9 <= len(digits) <= 12:
            pivots.append(
                {
                    "value": "0" + digits,
                    "type": "phone",
                    "reason": f"Nomor akun e-wallet {bank_name}",
                }
            )

        # Actionable Indonesian anti-fraud check links
        q_num = quote(f'"{digits}"')
        q_bank_num = quote(f'"{digits}" ({bank_code} OR penipu OR penipuan OR rekber OR rekening)')
        links = [
            ("CekRekening Komdigi (Resmi)", "https://cekrekening.id/home", f"Periksa nomor rekening {digits} ({bank_name}) di portal resmi pemerintah"),
            ("Cek Laporan di Kredibel.co.id", f"https://www.kredibel.co.id/search?q={quote(digits)}", f"Cari riwayat laporan korban untuk rekening {digits}"),
            ("Google Scam Dork Rekening", f"https://www.google.com/search?q={q_bank_num}", "Cari laporan penipuan rekening di blog, forum, dan berita"),
            ("Pencarian Twitter/X Laporan Korban", f"https://www.google.com/search?q=site:x.com+{q_num}", "Banyak korban penipuan mengunggah bukti transfer ke X/Twitter"),
            ("Pencarian Facebook Laporan Korban", f"https://www.google.com/search?q=site:facebook.com+{q_num}", "Cek unggahan blacklist grup jual-beli Facebook"),
        ]
        for title, url, desc in links:
            findings.append(
                Finding(
                    source=self.name,
                    category="investigation_link",
                    title=title,
                    value=desc,
                    url=url,
                    severity=Severity.INFO,
                    confidence=1.0,
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
            summary=f"Validasi & tautan cek rekening {bank_name} ({digits}) selesai.",
            pivot_candidates=pivots,
        )

    @staticmethod
    def _parse_bank_target(raw: str) -> tuple[str, str]:
        cleaned = raw.strip()
        if ":" in cleaned:
            prefix, rest = cleaned.split(":", 1)
            digits = re.sub(r"\D", "", rest)
            if digits:
                return prefix.strip().upper(), digits
        m = re.match(r"^([A-Za-z]+)[\s\-/]+(\d[\d\s\-]{5,})$", cleaned)
        if m:
            return m.group(1).upper(), re.sub(r"\D", "", m.group(2))
        digits = re.sub(r"\D", "", cleaned)
        return "BANK", digits
