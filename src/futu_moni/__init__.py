"""futu-moni: Standalone JP market data service via Futu native FT protocol.

No OpenD, no API key — intercepts FTNN's live session via MITM proxy.
Protocol adapted from github.com/bigbigmonkey123/futu-moni (MIT license).
"""

from futu_moni.adapter import FutuNativeConfig, ProxyQuoteClient
from futu_moni.models import FutuNativeReport
from futu_moni.proxy import ProxyConfig, ProxySession
from futu_moni.service import FutuNativeService, ServiceConfig, ServiceHealth, ServiceState

__all__ = [
    "FutuNativeConfig",
    "FutuNativeReport",
    "FutuNativeService",
    "ProxyConfig",
    "ProxyQuoteClient",
    "ProxySession",
    "ServiceConfig",
    "ServiceHealth",
    "ServiceState",
]
