"""Evaluation rules: turn a parsed Config into a Report."""

from __future__ import annotations

from . import protocols
from .ciphersuite import REGISTRY
from .config import Config
from .parser import expand_cipherstring
from .report import Issue, Report


_WEAK_SEVERITY = {
    "RC4": "high",
    "DES": "high",
    "3DES": "medium",
    "RC2": "high",
    "EXPORT": "high",
    "NULL encryption": "critical",
    "anonymous authentication (aNULL)": "high",
}


def evaluate(config: Config) -> Report:
    issues: list = []

    enabled_protocols = [p for p in protocols.PROTOCOLS if config.protocols.get(p)]
    for proto in enabled_protocols:
        if proto in protocols.DEPRECATED:
            issues.append(
                Issue(
                    name="deprecated_protocol",
                    evidence=f"Deprecated protocol enabled: {proto}",
                    severity=protocols.SEVERITY[proto],
                )
            )

    cipherstring = config.cipherstring if config.cipherstring else "DEFAULT"
    enabled_ciphers, seclevel = expand_cipherstring(cipherstring)
    for name in config.ciphersuites:
        if name not in enabled_ciphers:
            enabled_ciphers.append(name)

    for name in enabled_ciphers:
        suite = REGISTRY[name]
        for reason in suite.weak_reasons:
            issues.append(
                Issue(
                    name="weak_cipher",
                    evidence=f"Weak cipher suite enabled: {name} ({reason})",
                    severity=_WEAK_SEVERITY.get(reason, "medium"),
                )
            )

    if enabled_ciphers:
        if not any(REGISTRY[n].provides_pfs for n in enabled_ciphers):
            issues.append(
                Issue(
                    name="no_forward_secrecy",
                    evidence=(
                        "No ECDHE/DHE cipher suites enabled; connections do not "
                        "provide forward secrecy. Enabled suites: "
                        + ", ".join(enabled_ciphers)
                    ),
                    severity="medium",
                )
            )
    else:
        issues.append(
            Issue(
                name="no_ciphers_enabled",
                evidence="CipherString expansion produced an empty cipher list",
                severity="high",
            )
        )

    aead_available = any(REGISTRY[n].is_aead for n in enabled_ciphers)

    if seclevel is not None and seclevel < 1:
        issues.append(
            Issue(
                name="insecure_seclevel",
                evidence=(
                    f"@SECLEVEL={seclevel} disables OpenSSL security checks "
                    "(weak ciphers and short keys are permitted)"
                ),
                severity="medium",
            )
        )

    return Report(
        file=config.path,
        enabled_protocols=enabled_protocols,
        enabled_ciphers=enabled_ciphers,
        aead_available=aead_available,
        seclevel=seclevel,
        issues=issues,
    )

