"""CipherString expansion.

Implements OpenSSL-style list semantics:

* tokens are separated by ':' or ',' (whitespace also works);
* a bare token appends its matches to the list (if not already present);
* '+TOKEN' moves/appends matches to the end of the list;
* '-TOKEN' removes matches (they may be re-added later);
* '!TOKEN' removes matches permanently (they can never be re-added);
* 'DEFAULT' resets the list to the built-in baseline;
* '@SECLEVEL=n' records the security level;
* '@STRENGTH' sorts the final list by cipher strength.
"""

from __future__ import annotations

import re

from .ciphersuite import REGISTRY, TLS13_SUITES, default_cipher_names, strength_of


class CipherStringError(ValueError):
    pass


_TOKEN_SPLIT = re.compile(r"[:,\s]+")


def _alias_predicates():
    return {
        "ALL": lambda s: True,
        "aNULL": lambda s: s.auth == "aNULL",
        "eNULL": lambda s: s.enc == "NULL",
        "NULL": lambda s: s.enc == "NULL",
        "RC4": lambda s: s.enc == "RC4",
        "DES": lambda s: s.enc == "DES",
        "3DES": lambda s: s.enc == "3DES",
        "EXP": lambda s: s.export,
        "EXPORT": lambda s: s.export,
        "AESGCM": lambda s: "GCM" in s.enc,
        "CHACHA20": lambda s: "CHACHA20" in s.enc,
        "AES": lambda s: s.enc.startswith("AES"),
        "ECDHE": lambda s: s.kex == "ECDHE",
        "kECDHE": lambda s: s.kex == "ECDHE",
        "DHE": lambda s: s.kex == "DHE",
        "kDHE": lambda s: s.kex == "DHE",
        "EDH": lambda s: s.kex == "DHE",
        "kRSA": lambda s: s.kex == "RSA",
        "RSA": lambda s: s.kex == "RSA",
        "SHA": lambda s: s.mac == "SHA1",
        "SHA1": lambda s: s.mac == "SHA1",
        "SHA256": lambda s: s.mac == "SHA256",
        "SHA384": lambda s: s.mac == "SHA384",
        "MD5": lambda s: s.mac == "MD5",
        "HIGH": lambda s: not s.is_weak and s.mac != "MD5",
        "MEDIUM": lambda s: s.enc == "3DES",
        "LOW": lambda s: s.export or s.enc in ("DES", "RC2"),
    }


_ALIASES = _alias_predicates()


def match_token(token: str) -> list:
    """Resolve a single token (exact suite name or alias) to suite names."""
    if token in REGISTRY and token not in TLS13_SUITES:
        return [token]
    predicate = _ALIASES.get(token)
    if predicate is None:
        raise CipherStringError(f"unknown cipher or alias: {token!r}")
    return [
        name
        for name, suite in REGISTRY.items()
        if name not in TLS13_SUITES and predicate(suite)
    ]


def expand_cipherstring(cipherstring: str):
    """Expand a CipherString into (enabled_names, seclevel).

    seclevel is None when the string carries no @SECLEVEL directive.
    """
    enabled: list = []
    killed: set = set()
    seclevel = None
    sort_by_strength = False

    for raw in _TOKEN_SPLIT.split(cipherstring.strip()):
        if not raw:
            continue
        if raw.startswith("@"):
            directive = raw[1:]
            upper = directive.upper()
            if upper.startswith("SECLEVEL="):
                try:
                    seclevel = int(directive.split("=", 1)[1])
                except ValueError as exc:
                    raise CipherStringError(f"bad @SECLEVEL value: {raw!r}") from exc
            elif upper == "STRENGTH":
                sort_by_strength = True
            else:
                raise CipherStringError(f"unknown @-directive: {raw!r}")
            continue

        op = "add"
        if raw[0] in "+-!":
            op = {"+": "append", "-": "remove", "!": "kill"}[raw[0]]
            raw = raw[1:]
        if not raw:
            raise CipherStringError("dangling operator in CipherString")

        if raw == "DEFAULT":
            if op != "add":
                raise CipherStringError("DEFAULT does not take a +/-/-! prefix")
            enabled = [n for n in default_cipher_names() if n not in killed]
            continue

        matches = match_token(raw)
        if not matches:
            raise CipherStringError(f"{raw!r} matches no cipher suites")

        if op == "add":
            for name in matches:
                if name not in enabled and name not in killed:
                    enabled.append(name)
        elif op == "append":
            for name in matches:
                if name in killed:
                    continue
                if name in enabled:
                    enabled.remove(name)
                enabled.append(name)
        elif op == "remove":
            enabled = [n for n in enabled if n not in matches]
        elif op == "kill":
            enabled = [n for n in enabled if n not in matches]
            killed.update(matches)

    if sort_by_strength:
        enabled.sort(key=lambda n: -strength_of(n))
    return enabled, seclevel

