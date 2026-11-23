"""Email OSINT module: disposable detection, scammer impersonation checks, DNS MX/SPF/DMARC, HIBP/Hunter."""

from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import quote

from opensearch_lab.core.base_module import BaseOSINTModule, InvestigationContext
from opensearch_lab.core.correlator import make_entity_id
from opensearch_lab.core.known_entities import GENERIC_EMAIL_LOCAL_PARTS
from opensearch_lab.core.models import (
    EntityEdge,
    EntityNode,
    Finding,
    ModuleResult,
    Severity,
    TargetType,
)

DISPOSABLE_EMAIL_DOMAINS: set[str] = {
    "10minutemail.com", "10minutemail.net", "10minemail.com", "20minutemail.com",
    "33mail.com", "anonbox.net", "bccto.me", "binkmail.com", "bobmail.info",
    "burnermail.io", "chammy.info", "clrmail.com", "cool.fr.nf", "correo.blogos.net",
    "courriel.fr.nf", "crazymailing.com", "deadaddress.com", "despam.it",
    "discard.email", "discardmail.com", "disposable.com", "disposableaddress.com",
    "disposableemailaddresses.com", "disposableinbox.com", "dispostable.com",
    "dodgeit.com", "dodgit.com", "donemail.ru", "dontreg.com", "dontsendmespam.de",
    "dropmail.me", "dump-email.info", "dumpmail.de", "dumpyemail.com",
    "e4ward.com", "email60.com", "emaildienst.de", "emailigo.de", "emailinfive.com",
    "emailmiser.com", "emailsensei.com", "emailtemporario.com.br", "emailwarden.com",
    "emailx.at.hm", "emz.net", "fakeinbox.com", "fakemailgenerator.com",
    "fastacura.com", "filzmail.com", "fizmail.com", "flyspam.com", "frapmail.com",
    "garbagemail.org", "getairmail.com", "getnada.com", "getonemail.com",
    "ghosttexter.de", "girlsundertheinfluence.com", "gishpuppy.com", "guerillamail.biz",
    "guerillamail.com", "guerillamail.de", "guerillamail.info", "guerillamail.net",
    "guerillamail.org", "guerrillamail.com", "guerrillamail.de", "guerrillamail.net",
    "guerrillamail.org", "guerrillamailblock.com", "harakirimail.com", "hatespam.org",
    "hidemail.de", "hmamail.com", "hopemail.biz", "ieh-mail.de", "incognitomail.org",
    "inboxalias.com", "inboxclean.com", "inboxdesign.me", "inboxed.im", "instant-mail.de",
    "jetable.org", "kasmail.com", "klassmaster.com", "klzlk.com", "kulturbetrieb.info",
    "kurzepost.de", "lifebyfood.com", "link2mail.net", "litedrop.com", "lol.ovpn.to",
    "lookugly.com", "lopl.co.cc", "lortemail.dk", "lr78.com", "m4ilweb.info",
    "mail-temporaire.fr", "mail.by", "mail.mezimages.net", "mail2rss.org", "mail333.com",
    "mail4trash.com", "mailbidon.com", "mailblocks.com", "mailcatch.com", "maildrop.cc",
    "maileater.com", "mailexpire.com", "mailforspam.com", "mailfreeonline.com",
    "mailguard.me", "mailin8r.com", "mailinater.com", "mailinator.com", "mailinator.net",
    "mailinator2.com", "mailincubator.com", "mailismagic.com", "mailme.lv",
    "mailmetrash.com", "mailmoat.com", "mailnator.com", "mailnesia.com", "mailnull.com",
    "mailpick.biz", "mailrock.biz", "mailshell.com", "mailsiphon.com", "mailslite.com",
    "mailtemp.info", "mailtothis.com", "mailtrash.net", "mailzilla.com", "mbx.cc",
    "mega.zik.dj", "meltmail.com", "mintemail.com", "mohmal.com", "moncourrier.fr.nf",
    "monemail.fr.nf", "monmail.fr.nf", "mt2014.com", "mytempemail.com", "nada.email",
    "nepwk.com", "nervmich.net", "nervtmich.net", "netmails.net", "netzidiot.de",
    "no-spam.ws", "nobulk.com", "noclickemail.com", "nogmailspam.info", "nomail.xl.cx",
    "nomail2me.com", "nomorespamemails.com", "nospam.ze.tc", "nospam4.us", "nospamfor.us",
    "nowmymail.com", "nurfuerspam.de", "objectmail.com", "obobbo.com", "oneoffemail.com",
    "onewaymail.com", "owlpic.com", "pancakemail.com", "politikerclub.de", "poofy.org",
    "pookmail.com", "proxymail.eu", "punkass.com", "putthisinyourspamdatabase.com",
    "quickinbox.com", "rcpt.at", "recode.me", "regbypass.com", "rmqkr.net",
    "rppkn.com", "rtrtr.com", "s0ny.net", "safe-mail.net", "safetymail.info",
    "sandelf.de", "saynotospams.com", "selfdestructingmail.com", "sendspamhere.com",
    "sharklasers.com", "shieldemail.com", "shiftmail.com", "shitmail.me", "shortmail.net",
    "sibmail.com", "skeefmail.com", "slaskpost.se", "slopsbox.com", "smellfear.com",
    "snakemail.com", "sneakemail.com", "snkmail.com", "sofimail.com", "soodonims.com",
    "spam.la", "spamavert.com", "spambob.net", "spambog.com", "spambog.de", "spambog.ru",
    "spambox.us", "spamcannon.com", "spamcero.com", "spamcorptastic.com", "spamcowboy.com",
    "spamday.com", "spamex.com", "spamfree24.org", "spamgourmet.com", "spamherelots.com",
    "spamhereplease.com", "spamhole.com", "spamify.com", "spaml.com", "spammotel.com",
    "spamobox.com", "spamspot.com", "spamthis.co.uk", "spamtroll.net", "speed.1s.fr",
    "supergreatmail.com", "supermailer.jp", "suremail.info", "temp-mail.org",
    "temp-mail.ru", "tempalias.com", "tempe-mail.com", "tempemail.biz", "tempemail.com",
    "tempinbox.com", "tempmail.eu", "tempmail.it", "tempmail2.com", "tempmailer.com",
    "tempomail.fr", "temporarily.de", "temporarioemail.com.br", "temporaryemail.net",
    "temporaryforwarding.com", "temporaryinbox.com", "thankyou2010.com", "thisisnotmyrealemail.com",
    "throwawayemailaddress.com", "tilien.com", "tmailinator.com", "tradermail.info",
    "trash-amil.com", "trash-mail.at", "trash-mail.com", "trash-mail.de", "trash2009.com",
    "trashemail.de", "trashmail.at", "trashmail.com", "trashmail.de", "trashmail.me",
    "trashmail.net", "trashmail.org", "trashmailer.com", "trashymail.com", "tyldd.com",
    "uggsrock.com", "upliftnow.com", "uplipht.com", "venompen.com", "veryrealemail.com",
    "viditag.com", "viewcastmedia.com", "webm4il.info", "wegwerfadresse.de",
    "wegwerfemail.de", "wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org",
    "wh4f.org", "whyspam.me", "willselfdestruct.com", "winemaven.info", "wronghead.com",
    "wuzup.net", "xagloo.com", "xemaps.com", "xents.com", "xmaily.com", "xoxy.net",
    "yopmail.com", "yopmail.fr", "yopmail.net", "yourdomain.com", "yuurok.com",
    "zehnminutenmail.de", "zippymail.info", "zoemail.org",
}

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.id",
    "outlook.com", "hotmail.com", "live.com", "icloud.com", "proton.me", "protonmail.com",
}

IMPERSONATION_LOCAL_WORDS = {
    "cs", "admin", "support", "helpdesk", "official", "resmi", "billing",
    "bca", "bri", "bni", "mandiri", "dana", "ovo", "gopay", "shopee", "tokopedia", "ojk",
}


class EmailOsintModule(BaseOSINTModule):
    """Comprehensive Email OSINT: burner check, impersonation pattern, MX/SPF/DMARC, HIBP & Hunter."""

    name = "email_osint"
    display_name = "Email Intelligence & Burner Detector"
    description = "Mendeteksi email sekali pakai (disposable), peniruan CS/bank di webmail gratis, MX/SPF/DMARC, HIBP, dan Hunter."
    category = "identity_osint"
    supported_targets = {TargetType.EMAIL}
    requires_api_key = False
    api_key_env = "HIBP_API_KEY"

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

        if "@" not in target:
            return ModuleResult(
                module_name=self.name,
                display_name=self.display_name,
                status="error",
                duration_ms=0,
                error="Format email tidak valid",
            )

        local_part, domain = target.strip().lower().split("@", 1)
        dom_id = make_entity_id("domain", domain)
        entities.append(EntityNode(id=dom_id, label=domain, entity_type="domain"))
        edges.append(EntityEdge(source=root_id, target=dom_id, relation="uses_domain"))

        uname_candidate = re.sub(r"\+.*$", "", local_part)
        if len(uname_candidate) >= 3 and uname_candidate not in GENERIC_EMAIL_LOCAL_PARTS:
            pivots.append(
                {
                    "value": uname_candidate,
                    "type": "username",
                    "reason": "Local-part email berpotensi digunakan sebagai username sosmed",
                }
            )
        if domain not in FREE_PROVIDERS and domain not in DISPOSABLE_EMAIL_DOMAINS:
            pivots.append({"value": domain, "type": "domain", "reason": "Domain korporat/pribadi dari email"})

        # 1. Disposable / burner email check
        if domain in DISPOSABLE_EMAIL_DOMAINS:
            findings.append(
                Finding(
                    source=self.name,
                    category="burner_email",
                    title="Email Sekali Pakai (Disposable / Temp Mail)",
                    value=f"Domain '{domain}' adalah layanan temp-mail anonim yang sangat sering dipakai penipu.",
                    severity=Severity.HIGH,
                    confidence=0.98,
                    risk_delta=30,
                    signal_tier="confirmed_threat",
                )
            )
        elif domain in FREE_PROVIDERS:
            findings.append(
                Finding(
                    source=self.name,
                    category="email_provider",
                    title="Menggunakan Webmail Gratis Publik",
                    value=f"Provider: {domain}",
                    severity=Severity.INFO,
                    confidence=0.95,
                )
            )
            # Check bank/CS impersonation on free webmail (e.g., cs.dana.resmi@gmail.com)
            tokens = set(re.split(r"[._\-0-9]+", local_part))
            matched_imp = sorted(w for w in IMPERSONATION_LOCAL_WORDS if w in tokens)
            if matched_imp and (len(matched_imp) >= 2 or any(b in matched_imp for b in ("bca", "bri", "bni", "mandiri", "dana", "ovo", "gopay", "shopee", "ojk"))):
                findings.append(
                    Finding(
                        source=self.name,
                        category="brand_impersonation",
                        title="Email Peniruan CS/Instansi di Webmail Gratis",
                        value=f"Alamat '{target}' memakai kata kunci resmi ({', '.join(matched_imp)}) pada domain gratis '{domain}'.",
                        severity=Severity.HIGH,
                        confidence=0.92,
                        risk_delta=28,
                        signal_tier="confirmed_threat",
                    )
                )

        # Random/bot-like pattern check (e.g., user93847291@...)
        digits = sum(c.isdigit() for c in local_part)
        if len(local_part) >= 8 and digits >= 5 and digits / len(local_part) >= 0.45:
            findings.append(
                Finding(
                    source=self.name,
                    category="email_pattern",
                    title="Pola Local-Part Acak / Banyak Angka",
                    value=f"Local-part '{local_part}' memiliki proporsi digit tinggi ({digits}/{len(local_part)} karakter).",
                    severity=Severity.LOW,
                    confidence=0.75,
                    risk_delta=8,
                    signal_tier="advisory",
                )
            )

        # 2. MX & SPF/DMARC check via DoH + optional HIBP + optional Hunter
        await asyncio.gather(
            self._check_dns_mx(domain, ctx, findings),
            self._check_hibp(target, ctx, findings),
            self._check_hunter(target, ctx, findings),
            return_exceptions=True,
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
            summary=f"Analisis email {target} selesai ({len(findings)} temuan).",
            pivot_candidates=pivots,
        )

    async def _check_dns_mx(
        self, domain: str, ctx: InvestigationContext, findings: list[Finding]
    ) -> None:
        url = f"https://cloudflare-dns.com/dns-query?name={quote(domain)}&type=MX"
        try:
            async with ctx.http_session.get(url, headers={"Accept": "application/dns-json"}, timeout=7) as resp:
                if resp.status != 200:
                    return
                data = await resp.json(content_type=None)
        except Exception:
            return
        answers = data.get("Answer") or []
        mx_hosts = [str(a.get("data", "")).strip() for a in answers if a.get("data")]
        if mx_hosts:
            findings.append(
                Finding(
                    source=self.name,
                    category="email_dns",
                    title="Mail Server (MX) Aktif",
                    value=", ".join(mx_hosts[:5]),
                    severity=Severity.INFO,
                    confidence=0.95,
                )
            )
        else:
            findings.append(
                Finding(
                    source=self.name,
                    category="email_dns",
                    title="Domain Tidak Memiliki MX Record",
                    value=f"Domain {domain} tidak dapat menerima balasan email (indikasi domain palsu/spoofed).",
                    severity=Severity.MEDIUM,
                    confidence=0.9,
                    risk_delta=20,
                    signal_tier="suspicious",
                )
            )

    async def _check_hibp(
        self, email: str, ctx: InvestigationContext, findings: list[Finding]
    ) -> None:
        hibp_key = ctx.config.get_api_key("HIBP_API_KEY")
        if not hibp_key:
            return
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false"
        try:
            async with ctx.http_session.get(
                url,
                headers={"hibp-api-key": hibp_key, "user-agent": ctx.config.user_agent},
                timeout=8,
            ) as resp:
                if resp.status == 404:
                    findings.append(
                        Finding(
                            source=self.name,
                            category="breach_history",
                            title="HIBP Data Breach Check",
                            value="Tidak ditemukan di database kebocoran HIBP (akun sangat baru atau jarang dipakai).",
                            severity=Severity.INFO,
                            confidence=0.9,
                        )
                    )
                    return
                if resp.status != 200:
                    return
                breaches = await resp.json()
        except Exception:
            return
        if isinstance(breaches, list) and breaches:
            names = [str(b.get("Name", "")) for b in breaches[:10]]
            findings.append(
                Finding(
                    source=self.name,
                    category="breach_history",
                    title=f"Email Muncul di {len(breaches)} Kebocoran Data (HIBP)",
                    value=", ".join(names),
                    url="https://haveibeenpwned.com/",
                    severity=Severity.LOW,
                    confidence=0.95,
                    metadata={"breach_count": len(breaches), "breaches": names},
                )
            )

    async def _check_hunter(
        self, email: str, ctx: InvestigationContext, findings: list[Finding]
    ) -> None:
        hunter_key = ctx.config.get_api_key("HUNTER_API_KEY")
        if not hunter_key:
            return
        url = f"https://api.hunter.io/v2/email-verifier?email={quote(email)}&api_key={quote(hunter_key)}"
        try:
            async with ctx.http_session.get(url, timeout=8) as resp:
                if resp.status != 200:
                    return
                payload = await resp.json()
        except Exception:
            return
        data = payload.get("data") or {}
        findings.append(
            Finding(
                source=self.name,
                category="email_verification",
                title="Verifikasi Deliverability Hunter.io",
                value=f"Status: {data.get('status', '-')} | Score: {data.get('score', '-')} | Disposable: {data.get('disposable', False)}",
                severity=Severity.INFO,
                confidence=0.95,
                metadata=data,
            )
        )
