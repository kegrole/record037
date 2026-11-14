"""Protocol version knowledge."""

from __future__ import annotations

# Canonical protocol names in preference order.
PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")

# Anything here is considered dangerous when enabled.
DEPRECATED = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")

SEVERITY = {
    "SSLv2": "critical",
    "SSLv3": "critical",
    "TLSv1": "high",
    "TLSv1.1": "high",
}

_ALIASES = {
    "sslv2": "SSLv2",
    "ssl2": "SSLv2",
    "sslv3": "SSLv3",
    "ssl3": "SSLv3",
    "tlsv1": "TLSv1",
    "tls1": "TLSv1",
    "tls1.0": "TLSv1",
    "tlsv1.0": "TLSv1",
    "tlsv1.1": "TLSv1",
    "tls1.1": "TLSv1.1",
    "tlsv1.2": "TLSv1.2",
    "tls1.2": "TLSv1.2",
    "tlsv1.3": "TLSv1.3",
    "tls1.3": "TLSv1.3",
}


def canonical(name: str):
    """Map a config key like 'TLSv1.2' or 'ssl3' to a canonical name, or None."""
    return _ALIASES.get(name.strip().lower())
