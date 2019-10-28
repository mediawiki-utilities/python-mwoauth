"""
A set of stateless functions that can be used to complete various steps of an
OAuth handshake or to identify a MediaWiki user.

:Example:
    .. code-block:: python

        from mwoauth import ConsumerToken, initiate, complete, identify
        from six.moves import input # For compatibility between python 2 and 3

        # Consruct a "consumer" from the key/secret provided by MediaWiki
        import config
        consumer_token = ConsumerToken(
            config.consumer_key, config.consumer_secret)
        mw_uri = "https://en.wikipedia.org/w/index.php"

        # Step 1: Initialize -- ask MediaWiki for a temporary key/secret for
        # user
        redirect, request_token = initiate(mw_uri, consumer_token)

        # Step 2: Authorize -- send user to MediaWiki to confirm authorization
        print("Point your browser to: %s" % redirect) #
        response_qs = input("Response query string: ")

        # Step 3: Complete -- obtain authorized key/secret for "resource owner"
        access_token = complete(
            mw_uri, consumer_token, request_token, response_qs)
        print(str(access_token))

        # Step 4: Identify -- (optional) get identifying information about the
        # user
        identity = identify(mw_uri, consumer_token, access_token)
        print("Identified as {username}.".format(**identity))
"""
import json
import re
import time

import jwt
import requests
from requests_oauthlib import OAuth1
from six import PY3, text_type

from six.moves.urllib.parse import parse_qs, urlencode, urlparse

from . import defaults
from .errors import OAuthException
from .tokens import AccessToken, RequestToken


def force_unicode(val, encoding="unicode-escape"):
    if type(val) == text_type:
        return val
    else:
        if PY3:
            return val.decode(encoding, errors="replace")
        else:
            return unicode(val, encoding, errors="replace")  # noqa


def initiate(mw_uri, consumer_token, callback='oob',
             user_agent=defaults.USER_AGENT):
    """
    Initiate an oauth handshake with MediaWiki.

    :Parameters:
        mw_uri : `str`
            The base URI of the MediaWiki installation.  Note that the URI
            should end in ``"index.php"``.
        consumer_token : :class:`~mwoauth.ConsumerToken`
            A token representing you, the consumer.  Provided by MediaWiki via
            ``Special:OAuthConsumerRegistration``.
        callback : `str`
            Callback URL. Defaults to 'oob'.

    :Returns:
        A `tuple` of two values:

        * a MediaWiki URL to direct the user to
        * a :class:`~mwoauth.RequestToken` representing a request for access


    """
    auth = OAuth1(consumer_token.key,
                  client_secret=consumer_token.secret,
                  callback_uri=callback)

    r = requests.post(url=mw_uri,
                      params={'title': "Special:OAuth/initiate"},
                      auth=auth,
                      headers={'User-Agent': user_agent})

    request_token = process_request_token(r.text)

    params = {'title': "Special:OAuth/authenticate",
              'oauth_token': request_token.key,
              'oauth_consumer_key': consumer_token.key}

    return (mw_uri + "?" + urlencode(params), request_token)


def process_request_token(content):
    if content.startswith("Error: "):
        raise OAuthException(content[len("Error: "):])

    credentials = parse_qs(content)

    if credentials is None or credentials == {}:
        raise OAuthException(
            "Expected x-www-form-urlencoded response from " +
            "MediaWiki, but got something else: " +
            "{0}".format(repr(content)))
    elif 'oauth_token' not in credentials or \
         'oauth_token_secret' not in credentials:
        raise OAuthException(
            "MediaWiki response lacks token information: "
            "{0}".format(repr(credentials)))
    else:
        return RequestToken(
            credentials.get('oauth_token')[0],
            credentials.get('oauth_token_secret')[0]
        )


def complete(mw_uri, consumer_token, request_token, response_qs,
             user_agent=defaults.USER_AGENT):
    """
    Complete an OAuth handshake with MediaWiki by exchanging an

    :Parameters:
        mw_uri : `str`
            The base URI of the MediaWiki installation.  Note that the URI
            should end in ``"index.php"``.
        consumer_token : :class:`~mwoauth.ConsumerToken`
            A key/secret pair representing you, the consumer.
        request_token : :class:`~mwoauth.RequestToken`
            A temporary token representing the user.  Returned by
            `initiate()`.
        response_qs : `bytes`
            The query string of the URL that MediaWiki forwards the user back
            after authorization.

    :Returns:
        An `AccessToken` containing an authorized key/secret pair that
        can be stored and used by you.
    """

    callback_data = parse_qs(force_unicode(response_qs))

    if callback_data is None or callback_data == {}:
        raise OAuthException(
            "Expected URL query string, but got " +
            "something else instead: {0}".format(str(response_qs)))

    elif 'oauth_token' not in callback_data or \
         'oauth_verifier' not in callback_data:
        raise OAuthException(
            "Query string lacks token information: "
            "{0}".format(repr(callback_data)))

    # Process the callback_data
    request_token_key = callback_data.get('oauth_token')[0]
    verifier = callback_data.get('oauth_verifier')[0]

    # Check if the query string references the right temp resource owner key
    if not request_token.key == request_token_key:
        raise OAuthException(
            "Unexpect request token key {0!r}, expected {1!r}.".format(
                request_token_key, request_token.key))

    # Construct a new auth with the verifier
    auth = OAuth1(consumer_token.key,
                  client_secret=consumer_token.secret,
                  resource_owner_key=request_token.key,
                  resource_owner_secret=request_token.secret,
                  verifier=verifier)

    # Send the verifier and ask for an authorized resource owner key/secret
    r = requests.post(url=mw_uri,
                      params={'title': "Special:OAuth/token"},
                      auth=auth,
                      headers={'User-Agent': user_agent})

    # Parse response and construct an authorized resource owner
    credentials = parse_qs(r.text)

    if credentials is None:
        raise OAuthException(
            "Expected x-www-form-urlencoded response, " +
            "but got some else instead: {0}".format(r.text))

    access_token = AccessToken(
        credentials.get('oauth_token')[0],
        credentials.get('oauth_token_secret')[0]
    )

    return access_token


def identify(mw_uri, consumer_token, access_token, leeway=10.0,
             user_agent=defaults.USER_AGENT):
    """
    Gather identifying information about a user via an authorized token.

    :Parameters:
        mw_uri : `str`
            The base URI of the MediaWiki installation.  Note that the URI
            should end in ``"index.php"``.
        consumer_token : :class:`~mwoauth.ConsumerToken`
            A token representing you, the consumer.
        access_token : :class:`~mwoauth.AccessToken`
            A token representing an authorized user.  Obtained from
            `complete()`
        leeway : `int` | `float`
            The number of seconds of leeway to account for when examining a
            tokens "issued at" timestamp.

    :Returns:
        A dictionary containing identity information.
    """

    # Construct an OAuth auth
    auth = OAuth1(consumer_token.key,
                  client_secret=consumer_token.secret,
                  resource_owner_key=access_token.key,
                  resource_owner_secret=access_token.secret)

    # Request the identity using auth
    r = requests.post(url=mw_uri,
                      params={'title': "Special:OAuth/identify"},
                      auth=auth,
                      headers={'User-Agent': user_agent})

    # Special:OAuth/identify unhelpfully returns 200 status even when there is
    # an error in the API call. Check for error messages manually.
    try:
        identity = jwt.decode(r.content, consumer_token.secret,
                              audience=consumer_token.key,
                              algorithms=["HS256"],
                              leeway=leeway)
    except jwt.InvalidTokenError as e:
        if r.text.startswith('{'):
            try:
                resp = json.loads(r.text)
                if 'error' in resp:
                    raise OAuthException(
                        "A MediaWiki API error occurred: {0}"
                        .format(resp['message']))
                else:
                    raise OAuthException(
                        "Unknown JSON response: {0!r}"
                        .format(r.text[:100]))
            except ValueError as e:
                raise OAuthException(
                    "An error occurred while trying to read json " +
                    "content: {0}".format(e))
        else:
            raise OAuthException(
                "Could not read response from 'Special:OAuth/identify'.  " +
                "Maybe your MediaWiki is not configured correctly?  " +
                "Expected JSON but instead got: {0!r}".format(r.text[:100]))

    # Verify the issuer is who we expect (server sends $wgCanonicalServer)
    issuer = urlparse(identity['iss']).netloc
    expected_domain = urlparse(mw_uri).netloc
    if not issuer == expected_domain:
        raise OAuthException(
            "Unexpected issuer " +
            "{0}, expected {1}".format(issuer, expected_domain))

    # Check that the identity was issued in the past.
    now = time.time()
    issued_at = float(identity['iat'])
    if not now >= (issued_at - leeway):
        raise OAuthException(
            "Identity issued {0} ".format(issued_at - now) +
            "seconds in the future!")

    # Verify that the nonce matches our request nonce,
    # to avoid a replay attack
    authorization_header = force_unicode(r.request.headers['Authorization'])
    request_nonce = re.search(r'oauth_nonce="(.*?)"',
                              authorization_header).group(1)
    if identity['nonce'] != request_nonce:
        raise OAuthException(
            'Replay attack detected: {0} != {1}'.format(
                identity['nonce'], request_nonce))

    return identity
