"""TLS verification against the bundled Freebox root CAs."""

from __future__ import annotations

import ssl
from functools import lru_cache


@lru_cache(maxsize=4)
def freebox_ssl_context(cafile: str) -> ssl.SSLContext:
    """An SSL context that trusts ONLY the bundled Freebox root CAs (passing a
    cafile skips the system store), with hostname checking and TLS >= 1.2."""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
