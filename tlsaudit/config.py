"""Parsing of OpenSSL-style audit config files.

Format (one directive per line, '#' and ';' start comments, '[section]'
headers are accepted and ignored):

    TLSv1.2 = server            # enable a protocol (server/client/on/...)
    SSLv3 = off                 # explicitly disable one
    CipherString = DEFAULT:!aNULL:+RC4-SHA
    Ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256

When no protocol directive appears at all, TLSv1.2 and TLSv1.3 are
assumed enabled (a modern OpenSSL default).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import protocols
from .ciphersuite import TLS13_SUITES


class ConfigError(ValueError):
    pass


_ON_VALUES = {"server", "client", "on", "yes", "true", "1", "enable", "enabled"}
_OFF_VALUES = {"none", "off", "no", "false", "0", "disable", "disabled"}
_SUITE_SPLIT = re.compile(r"[:,\s]+")


@dataclass
class Config:
    path: str
    protocols: dict = field(default_factory=dict)   # canonical name -> bool
    cipherstring: str = None
    ciphersuites: list = field(default_factory=list)


def _parse_switch(value: str, lineno: int, key: str) -> bool:
    lowered = value.strip().lower()
    if lowered in _ON_VALUES:
        return True
    if lowered in _OFF_VALUES:
        return False
    raise ConfigError(f"line {lineno}: bad value {value!r} for {key}")


def parse_config(text: str, path: str = "<string>") -> Config:
    proto_flags = {}
    cipherstring = None
    ciphersuites: list = []
    saw_protocol_directive = False

    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            continue
        if "=" not in line:
            raise ConfigError(f"{path}:{lineno}: expected 'key = value', got {line!r}")
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.split("#", 1)[0].split(";", 1)[0].strip()

        canonical = protocols.canonical(key)
        if canonical is not None:
            saw_protocol_directive = True
            proto_flags[canonical] = _parse_switch(value, lineno, key)
        elif key.lower() == "cipherstring":
            cipherstring = value
        elif key.lower() == "ciphersuites":
            for token in _SUITE_SPLIT.split(value):
                if not token:
                    continue
                if token not in TLS13_SUITES:
                    raise ConfigError(
                        f"{path}:{lineno}: unknown TLS 1.3 ciphersuite {token!r}"
                    )
                if token not in ciphersuites:
                    ciphersuites.append(token)
        else:
            # Unknown directives are ignored, like OpenSSL ignores
            # settings it does not understand.
            continue

    if not saw_protocol_directive:
        proto_flags = {"TLSv1.2": True, "TLSv1.3": True}

    return Config(
        path=path,
        protocols=proto_flags,
        cipherstring=cipherstring,
        ciphersuites=ciphersuites,
    )


def load_config(path) -> Config:
    with open(path, "r", encoding="utf-8") as handle:
        return parse_config(handle.read(), path=str(path))

