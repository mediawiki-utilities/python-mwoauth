"""Provides a collection of utilities for easily working with MediaWiki's
OAuth1.0a implementation."""
from .handshaker import Handshaker
from .tokens import AccessToken, ConsumerToken, RequestToken
from .functions import initiate, complete, identify
from .about import (__name__, __version__, __author__, __author_email__,
                    __description__, __license__, __url__)


__all__ = [
    AccessToken,
    complete,
    ConsumerToken,
    Handshaker,
    identify,
    initiate,
    RequestToken,
    __name__, __version__, __author__, __author_email__,
    __description__, __license__, __url__
]
