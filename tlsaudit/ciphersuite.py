"""Cipher suite registry and classification helpers.

The registry is a small, self-contained table of common OpenSSL cipher
suite names together with the metadata the auditor needs: key exchange,
authentication, encryption, MAC and export grade.  Everything is derived
from this table, so classification never depends on a specific config.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CipherSuite:
    name: str
    kex: str        # ECDHE, DHE, RSA, ADH (anonymous)
    auth: str       # RSA, ECDSA, aNULL
    enc: str        # AES128-GCM, AES256-CBC, CHACHA20-POLY1305, RC4, 3DES, DES, RC2, NULL
    mac: str        # SHA1, SHA256, SHA384, MD5, AEAD
    export: bool = False
    protocol: str = "TLSv1"   # minimum/only protocol family; TLSv1.3 suites are separate

    @property
    def is_aead(self) -> bool:
        return any(tag in self.enc for tag in ("GCM", "CHACHA20", "CCM"))

    @property
    def provides_pfs(self) -> bool:
        """Forward secrecy requires an ephemeral (EC)DHE key exchange."""
        return self.kex in ("ECDHE", "DHE")

    @property
    def weak_reasons(self) -> tuple:
        reasons = []
        if self.enc == "RC4":
            reasons.append("RC4")
        if self.enc == "DES":
            reasons.append("DES")
        if self.enc == "3DES":
            reasons.append("3DES")
        if self.enc == "RC2":
            reasons.append("RC2")
        if self.export:
            reasons.append("EXPORT")
        if self.enc == "NULL":
            reasons.append("NULL encryption")
        if self.auth == "aNULL":
            reasons.append("anonymous authentication (aNULL)")
        return tuple(reasons)

    @property
    def is_weak(self) -> bool:
        return bool(self.weak_reasons)


def _build_registry() -> dict:
    defs = [
        # name, kex, auth, enc, mac, export, protocol
        # --- TLS 1.3 (selected via the ciphersuites directive) ---
        ("TLS_AES_256_GCM_SHA384", "ECDHE", "", "AES256-GCM", "AEAD", False, "TLSv1.3"),
        ("TLS_AES_128_GCM_SHA256", "ECDHE", "", "AES128-GCM", "AEAD", False, "TLSv1.3"),
        ("TLS_CHACHA20_POLY1305_SHA256", "ECDHE", "", "CHACHA20-POLY1305", "AEAD", False, "TLSv1.3"),
        ("TLS_AES_128_CCM_SHA256", "ECDHE", "", "AES128-CCM", "AEAD", False, "TLSv1.3"),
        # --- ECDHE ---
        ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE", "ECDSA", "AES256-GCM", "SHA384"),
        ("ECDHE-RSA-AES256-GCM-SHA384", "ECDHE", "RSA", "AES256-GCM", "SHA384"),
        ("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE", "ECDSA", "CHACHA20-POLY1305", "SHA256"),
        ("ECDHE-RSA-CHACHA20-POLY1305", "ECDHE", "RSA", "CHACHA20-POLY1305", "SHA256"),
        ("ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE", "ECDSA", "AES128-GCM", "SHA256"),
        ("ECDHE-RSA-AES128-GCM-SHA256", "ECDHE", "RSA", "AES128-GCM", "SHA256"),
        ("ECDHE-ECDSA-AES256-SHA384", "ECDHE", "ECDSA", "AES256-CBC", "SHA384"),
        ("ECDHE-RSA-AES256-SHA384", "ECDHE", "RSA", "AES256-CBC", "SHA384"),
        ("ECDHE-ECDSA-AES128-SHA256", "ECDHE", "ECDSA", "AES128-CBC", "SHA256"),
        ("ECDHE-RSA-AES128-SHA256", "ECDHE", "RSA", "AES128-CBC", "SHA256"),
        ("ECDHE-ECDSA-AES256-SHA", "ECDHE", "ECDSA", "AES256-CBC", "SHA1"),
        ("ECDHE-RSA-AES256-SHA", "ECDHE", "RSA", "AES256-CBC", "SHA1"),
        ("ECDHE-ECDSA-AES128-SHA", "ECDHE", "ECDSA", "AES128-CBC", "SHA1"),
        ("ECDHE-RSA-AES128-SHA", "ECDHE", "RSA", "AES128-CBC", "SHA1"),
        ("ECDHE-RSA-DES-CBC3-SHA", "ECDHE", "RSA", "3DES", "SHA1"),
        # --- DHE ---
        ("DHE-RSA-AES256-GCM-SHA384", "DHE", "RSA", "AES256-GCM", "SHA384"),
        ("DHE-RSA-AES128-GCM-SHA256", "DHE", "RSA", "AES128-GCM", "SHA256"),
        ("DHE-RSA-CHACHA20-POLY1305", "DHE", "RSA", "CHACHA20-POLY1305", "SHA256"),
        ("DHE-RSA-AES256-SHA256", "DHE", "RSA", "AES256-CBC", "SHA256"),
        ("DHE-RSA-AES128-SHA256", "DHE", "RSA", "AES128-CBC", "SHA256"),
        ("DHE-RSA-AES256-SHA", "DHE", "RSA", "AES256-CBC", "SHA1"),
        ("DHE-RSA-AES128-SHA", "DHE", "RSA", "AES128-CBC", "SHA1"),
        ("DHE-RSA-DES-CBC3-SHA", "DHE", "RSA", "3DES", "SHA1"),
        # --- static RSA key transport (no forward secrecy) ---
        ("AES256-GCM-SHA384", "RSA", "RSA", "AES256-GCM", "SHA384"),
        ("AES128-GCM-SHA256", "RSA", "RSA", "AES128-GCM", "SHA256"),
        ("AES256-SHA256", "RSA", "RSA", "AES256-CBC", "SHA256"),
        ("AES128-SHA256", "RSA", "RSA", "AES128-CBC", "SHA256"),
        ("AES256-SHA", "RSA", "RSA", "AES256-CBC", "SHA1"),
        ("AES128-SHA", "RSA", "RSA", "AES128-CBC", "SHA1"),
        # --- weak / legacy ---
        ("DES-CBC3-SHA", "RSA", "RSA", "3DES", "SHA1"),
        ("RC4-SHA", "RSA", "RSA", "RC4", "SHA1"),
        ("RC4-MD5", "RSA", "RSA", "RC4", "MD5"),
        ("DES-CBC-SHA", "RSA", "RSA", "DES", "SHA1"),
        ("EXP-DES-CBC-SHA", "RSA", "RSA", "DES", "SHA1", True),
        ("EXP-RC4-MD5", "RSA", "RSA", "RC4", "MD5", True),
        ("EXP-RC2-CBC-MD5", "RSA", "RSA", "RC2", "MD5", True),
        ("NULL-SHA256", "RSA", "RSA", "NULL", "SHA256"),
        ("NULL-SHA", "RSA", "RSA", "NULL", "SHA1"),
        ("NULL-MD5", "RSA", "RSA", "NULL", "MD5"),
        # --- anonymous (aNULL) ---
        ("ADH-AES256-GCM-SHA384", "ADH", "aNULL", "AES256-GCM", "SHA384"),
        ("ADH-AES128-GCM-SHA256", "ADH", "aNULL", "AES128-GCM", "SHA256"),
        ("ADH-AES256-SHA", "ADH", "aNULL", "AES256-CBC", "SHA1"),
        ("ADH-AES128-SHA", "ADH", "aNULL", "AES128-CBC", "SHA1"),
        ("ADH-DES-CBC3-SHA", "ADH", "aNULL", "3DES", "SHA1"),
        ("ADH-RC4-MD5", "ADH", "aNULL", "RC4", "MD5"),
    ]
    registry = {}
    for row in defs:
        name, kex, auth, enc, mac = row[:5]
        export = row[5] if len(row) > 5 else False
        protocol = row[6] if len(row) > 6 else "TLSv1"
        registry[name] = CipherSuite(name, kex, auth, enc, mac, export, protocol)
    return registry


REGISTRY = _build_registry()

TLS13_SUITES = frozenset(
    name for name, suite in REGISTRY.items() if suite.protocol == "TLSv1.3"
)


def default_cipher_names() -> list:
    """The DEFAULT baseline: everything except weak/NULL/EXPORT/MD5 suites.

    TLS 1.3 suites are excluded; OpenSSL selects those via the separate
    ciphersuites directive, not via CipherString.
    """
    return [
        name
        for name, suite in REGISTRY.items()
        if suite.protocol != "TLSv1.3"
        and not suite.is_weak
        and suite.mac != "MD5"
    ]


_STRENGTH_BITS = {
    "AES256-GCM": 256,
    "CHACHA20-POLY1305": 256,
    "AES256-CCM": 256,
    "AES256-CBC": 256,
    "AES128-GCM": 128,
    "AES128-CCM": 128,
    "AES128-CBC": 128,
    "RC4": 128,
    "3DES": 112,
    "DES": 56,
    "RC2": 40,
    "NULL": 0,
}


def strength_of(name: str) -> int:
    return _STRENGTH_BITS.get(REGISTRY[name].enc, 0)

