# -*- coding: UTF-8 -*-
import pytest
from six import PY3, b

from ..errors import OAuthException
from ..functions import process_request_token


def test_process_request_token():
    request_token = process_request_token(
        b("oauth_token=iamatoken&oauth_token_secret=iamasecret"))
    assert request_token.key == "iamatoken"
    assert request_token.secret == "iamasecret"


def test_process_request_token_errors():
    if PY3:
        text = "Error: Произошла ошибка в протоколе OAuth: " + \
               "Invalid consumer key"
        content = bytes(text, "utf-8")
    else:
        content = "Error: Произошла ошибка в протоколе OAuth: " + \
                  "Invalid consumer key"
        text = unicode(content, "utf-8")
    with pytest.raises(OAuthException, match=text[len("Error: "):]):
        process_request_token(content)

    with pytest.raises(OAuthException, match="I am an error"):
        process_request_token("Error: I am an error")

    with pytest.raises(OAuthException, match=r"Expected x-www-form-.*"):
        process_request_token("TOTAL NONSENSE")

    with pytest.raises(OAuthException, match=r"MediaWiki response lacks.*"):
        process_request_token("foo=bar&baz=bum")
