"""Cryptocurrency wallet OSINT module (BTC, ETH/EVM, TRON, Solana) with free public explorer APIs."""

from __future__ import annotations

import time
from urllib.parse import quote

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.detector import BTC_RE, ETH_RE, SOLANA_RE, TRON_RE
from opensearch_lab.core.models import Finding, ModuleResult, Severity, TargetType


def _detect_chain(address: str) -> str:
    if BTC_RE.match(address):
        return "Bitcoin (BTC)"
    if ETH_RE.match(address):
        return "Ethereum / EVM"
    if TRON_RE.match(address):
        return "TRON (TRC20)"
    if SOLANA_RE.match(address):
        return "Solana (SOL)"
    return "Unknown Chain"


class CryptoOsintModule(BaseOSINTModule):
    """Traces blockchain wallet balances, tx counts, and scam database links."""

    name = "crypto_osint"
    display_name = "Crypto Wallet & Scam Tracer"
    description = "Identifikasi jaringan wallet (BTC/ETH/TRON/SOL), cek saldo/transaksi on-chain, dan link ke Chainabuse."
    category = "financial_osint"
    supported_targets = {TargetType.CRYPTO_WALLET}
    requires_api_key = False
    api_key_env = "ETHERSCAN_API_KEY"

    async def run(
        self,
        target: str,
        target_type: TargetType,
        ctx: InvestigationContext,
    ) -> ModuleResult:
        started = time.perf_counter()
        addr = target.strip()
        chain = _detect_chain(addr)
        findings: list[Finding] = [
            Finding(
                source=self.name,
                category="crypto_chain",
                title="Identifikasi Jaringan Blockchain",
                value=f"Address: {addr} | Chain: {chain}",
                severity=Severity.INFO,
                confidence=0.96,
                metadata={"chain": chain},
            )
        ]

        if chain == "Bitcoin (BTC)":
            await self._query_btc(addr, ctx, findings)
            findings.append(
                Finding(
                    source=self.name,
                    category="explorer_link",
                    title="Mempool.space Explorer",
                    value="Lihat graf UTXO dan riwayat transaksi BTC",
                    url=f"https://mempool.space/address/{quote(addr)}",
                    severity=Severity.INFO,
                    confidence=1.0,
                )
            )
        elif chain == "Ethereum / EVM":
            await self._query_eth(addr, ctx, findings)
            findings.append(
                Finding(
                    source=self.name,
                    category="explorer_link",
                    title="Etherscan & Arkham Explorer",
                    value="Inspeksi transaksi ETH/ERC20 & label entitas",
                    url=f"https://etherscan.io/address/{quote(addr)}",
                    severity=Severity.INFO,
                    confidence=1.0,
                )
            )
        elif chain == "TRON (TRC20)":
            await self._query_tron(addr, ctx, findings)
            findings.append(
                Finding(
                    source=self.name,
                    category="explorer_link",
                    title="Tronscan Explorer",
                    value="Lihat transfer USDT-TRC20 dan riwayat alamat TRON",
                    url=f"https://tronscan.org/#/address/{quote(addr)}",
                    severity=Severity.INFO,
                    confidence=1.0,
                )
            )
        elif chain == "Solana (SOL)":
            findings.append(
                Finding(
                    source=self.name,
                    category="explorer_link",
                    title="Solscan Explorer",
                    value="Lihat riwayat transaksi dan token SPL Solana",
                    url=f"https://solscan.io/account/{quote(addr)}",
                    severity=Severity.INFO,
                    confidence=1.0,
                )
            )

        # Scam report databases
        findings.append(
            Finding(
                source=self.name,
                category="scam_database",
                title="Cek Laporan Scam di Chainabuse",
                value=f"Periksa apakah wallet {addr} pernah dilaporkan korban penipuan kripto",
                url=f"https://www.chainabuse.com/address/{quote(addr)}",
                severity=Severity.INFO,
                confidence=1.0,
            )
        )
        findings.append(
            Finding(
                source=self.name,
                category="scam_database",
                title="Breadcrumbs / Graph Tracing",
                value="Visualisasikan aliran dana wallet secara interaktif",
                url=f"https://www.breadcrumbs.app/reports/{quote(addr)}",
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
            summary=f"Analisis wallet {chain} selesai ({len(findings)} temuan).",
        )

    async def _query_btc(self, addr: str, ctx: InvestigationContext, findings: list[Finding]) -> None:
        url = f"https://blockstream.info/api/address/{quote(addr)}"
        try:
            async with ctx.http_session.get(url, timeout=8) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
        except Exception:
            return
        stats = data.get("chain_stats") or {}
        funded_sat = int(stats.get("funded_txo_sum", 0))
        spent_sat = int(stats.get("spent_txo_sum", 0))
        tx_count = int(stats.get("tx_count", 0))
        balance_btc = (funded_sat - spent_sat) / 1e8
        received_btc = funded_sat / 1e8
        findings.append(
            Finding(
                source=self.name,
                category="onchain_activity",
                title="Aktivitas On-Chain Bitcoin",
                value=f"Tx Count: {tx_count} | Total Diterima: {received_btc:.6f} BTC | Saldo: {balance_btc:.6f} BTC",
                url=f"https://blockstream.info/address/{quote(addr)}",
                severity=Severity.INFO,
                confidence=0.95,
                metadata={"tx_count": tx_count, "received_btc": received_btc, "balance_btc": balance_btc},
            )
        )

    async def _query_eth(self, addr: str, ctx: InvestigationContext, findings: list[Finding]) -> None:
        eth_key = ctx.config.get_api_key("ETHERSCAN_API_KEY")
        if eth_key:
            url = f"https://api.etherscan.io/api?module=account&action=balance&address={quote(addr)}&tag=latest&apikey={quote(eth_key)}"
            try:
                async with ctx.http_session.get(url, timeout=8) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "1":
                            bal_eth = int(data.get("result", 0)) / 1e18
                            findings.append(
                                Finding(
                                    source=self.name,
                                    category="onchain_activity",
                                    title="Saldo ETH (Etherscan)",
                                    value=f"Saldo: {bal_eth:.6f} ETH",
                                    url=f"https://etherscan.io/address/{quote(addr)}",
                                    severity=Severity.INFO,
                                    confidence=0.96,
                                )
                            )
                            return
            except Exception:
                pass

        # Free fallback via Blockscout public API
        try:
            async with ctx.http_session.get(
                f"https://eth.blockscout.com/api/v2/addresses/{quote(addr)}", timeout=8
            ) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
                coin_bal = int(data.get("coin_balance") or 0) / 1e18
                is_contract = bool(data.get("is_contract"))
                findings.append(
                    Finding(
                        source=self.name,
                        category="onchain_activity",
                        title="Aktivitas Alamat EVM (Blockscout)",
                        value=f"Saldo: {coin_bal:.6f} ETH | Smart Contract: {is_contract}",
                        url=f"https://eth.blockscout.com/address/{quote(addr)}",
                        severity=Severity.INFO,
                        confidence=0.92,
                        metadata={"is_contract": is_contract, "coin_balance_eth": coin_bal},
                    )
                )
        except Exception:
            pass

    async def _query_tron(self, addr: str, ctx: InvestigationContext, findings: list[Finding]) -> None:
        url = f"https://apilist.tronscanapi.com/api/accountv2?address={quote(addr)}"
        try:
            async with ctx.http_session.get(url, timeout=8) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
        except Exception:
            return
        trx_bal = int(data.get("balance", 0)) / 1e6
        tx_count = int(data.get("totalTransactionCount", 0))
        findings.append(
            Finding(
                source=self.name,
                category="onchain_activity",
                title="Aktivitas Wallet TRON / TRC20",
                value=f"Tx Count: {tx_count} | Saldo TRX: {trx_bal:.4f} TRX",
                url=f"https://tronscan.org/#/address/{quote(addr)}",
                severity=Severity.INFO,
                confidence=0.92,
                metadata={"tx_count": tx_count, "trx_balance": trx_bal},
            )
        )
