"""Precision domain parsing, subdomain depth calculation, and typosquatting helpers."""

from __future__ import annotations

MULTI_PART_TLDS: set[str] = {
    "co.id",
    "go.id",
    "ac.id",
    "or.id",
    "sch.id",
    "my.id",
    "web.id",
    "biz.id",
    "ponpes.id",
    "desa.id",
    "mil.id",
    "net.id",
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "com.sg",
    "edu.sg",
    "gov.sg",
    "com.my",
    "net.my",
    "gov.my",
    "co.jp",
    "ne.jp",
    "or.jp",
    "co.kr",
    "com.br",
    "com.ph",
    "com.vn",
    "co.th",
    "com.tw",
    "com.hk",
}

OFFICIAL_INSTITUTIONAL_SUFFIXES: tuple[str, ...] = (".go.id", ".ac.id", ".mil.id", ".gov", ".gov.uk", ".gov.sg", ".gov.au")


def clean_host(host: str) -> str:
    """Normalize a hostname by stripping whitespace, trailing dot, and port."""
    h = (host or "").strip().lower().rstrip(".")
    if ":" in h and not h.startswith("["):
        h = h.split(":", 1)[0]
    return h


def extract_registrable_domain(host: str) -> str:
    """Return the registrable apex domain (e.g., www.bca.co.id -> bca.co.id)."""
    h = clean_host(host)
    if not h or "." not in h:
        return h
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def extract_sld(host: str) -> str:
    """Return the second-level label of the registrable domain (e.g., bca.co.id -> bca)."""
    apex = extract_registrable_domain(host)
    if not apex:
        return ""
    return apex.split(".", 1)[0]


def subdomain_depth(host: str) -> int:
    """Count subdomain levels above the registrable domain, ignoring a single leading 'www.'."""
    h = clean_host(host)
    if h.startswith("www."):
        h = h[4:]
    apex = extract_registrable_domain(h)
    if not h or not apex or h == apex:
        return 0
    if h.endswith("." + apex):
        prefix = h[: -(len(apex) + 1)]
        return len([p for p in prefix.split(".") if p])
    return 0


def normalize_leet(text: str) -> str:
    """Map common homoglyph/leetspeak digits to letters for impersonation checks."""
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})
    return (text or "").lower().translate(table)


def levenshtein_distance(a: str, b: str) -> int:
    """Compute classic Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]
