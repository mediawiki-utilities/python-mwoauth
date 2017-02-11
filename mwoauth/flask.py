"""
.. autoclass:: mwoauth.flask.MWOAuth
  :members:
  :member-order: bysource

.. autofunction:: mwoauth.flask.authorized
"""

import logging
from functools import wraps

from flask import Blueprint, jsonify, redirect, request, session, url_for
from requests_oauthlib import OAuth1

from six.moves.urllib.parse import urljoin

from .errors import OAuthException
from .handshaker import Handshaker
from .tokens import AccessToken, RequestToken

logger = logging.getLogger(__name__)


class MWOAuth:
    """
    Implements a basic MediaWiki OAuth pattern with a set of routes
    * /mwoauth/initiate -- Starts an OAuth handshake
    * /mwoauth/callback -- Completes an OAuth handshake
    * /mwoauth/identify -- Gets identity information about an authorized user
    * /mwoauth/logout   -- Dicards OAuth tokens and user identity

    There's also a convenient decorator provided
    :func:`~mwoauth.flask.MWOAuth.authorized`.  When applied to a routing
    function, this decorator will redirect non-authorized users to
    /mwoauth/initiate with a "?next=" that will return them to the originating
    route once authorization is completed.

    :Example:
        .. code-block:: python

            from flask import Flask
            import mwoauth
            import mwoauth.flask

            app = Flask(__name__)

            @app.route("/")
            def index():
                return "Hello world"

            flask_mwoauth = mwoauth.flask.MWOAuth(
                "https://en.wikipedia.org",
                mwoauth.ConsumerToken("...", "..."))
            app.register_blueprint(flask_mwoauth.bp)

            @app.route("/my_settings/")
            @flask_mwoauth.authorized
            def my_settings():
                return flask_mwoauth.identity()

    :Parameters:
        host : str
            The host name (including protocol) of the MediaWiki wiki to use
            for the OAuth handshake.
        consumer_token : :class:`mwoauth.ConsumerToken`
            The consumer token information
        user_agent : str
            A User-Agent header to include with requests.  A warning will be
            logged is this is not set.
        default_next : str
            Where should the user be redirected after an OAuth handshake when
            no '?next=' param is provided
        render_logout : func
            A method that renders the logout page seen at /mwoauth/logout
        render_identify : func
            A method that renders the identify page seen at /mwoauth/identify.
            Takes one positional argument -- the `identity` dictionary returned
            by MediaWiki.
        render_error : func
            A method that renders an error.  Takes two arguements:

            * message : str (The error message)
            * status : int (The https status number)
        **kwargs : dict
            Parameters to be passed to :class:`flask.Blueprint` during
            its construction.
    """
    def __init__(self, host, consumer_token, user_agent=None,
                 default_next="index",
                 render_logout=None, render_indentify=None, render_error=None,
                 **kwargs):

        self.bp = Blueprint('mwoauth', __name__, **kwargs)
        self.host = host
        self.user_agent = user_agent
        self.consumer_token = consumer_token
        self.handshaker = None
        self.default_next = default_next
        self.render_logout = render_logout or generic_logout
        self.render_identify = render_indentify or generic_identify
        self.render_error = render_error or generic_error

        @self.bp.route("/mwoauth/initiate/")
        def mwoauth_initiate():
            """
            Starts an OAuth handshake.
            """
            mw_authorizer_url, request_token = self._handshaker().initiate()
            rt_session_key = _str(request_token.key) + "_request_token"
            next_session_key = _str(request_token.key) + "_next"

            # Ensures that Flask's default session storage strategy will work
            session[rt_session_key] = \
                dict(zip(request_token._fields, request_token))

            if 'next' in request.args:
                session[next_session_key] = request.args.get('next')

            return redirect(mw_authorizer_url)

        @self.bp.route("/mwoauth/callback/")
        def mwoauth_callback():
            """
            Completes the oauth handshake
            """
            # Generate session keys
            request_token_key = _str(request.args.get('oauth_token', 'None'))
            rt_session_key = request_token_key + "_request_token"
            next_session_key = request_token_key + "_next"

            # Make sure we're continuing an in-progress handshake
            if rt_session_key not in session:
                session.pop(rt_session_key, None)
                session.pop(next_session_key, None)
                return self.render_error(
                    "OAuth callback failed.  " +
                    "Couldn't find request_token in session. " +
                    "Are cookies disabled?", 403)

            # Complete the handshake
            try:
                access_token = self._handshaker().complete(
                    RequestToken(**session[rt_session_key]),
                    _str(request.query_string))
            except OAuthException as e:
                session.pop(rt_session_key, None)
                session.pop(next_session_key, None)
                return self.render_error(
                    "OAuth callback failed. " + str(e), 403)

            # Store the access token
            session['mwoauth_access_token'] = \
                dict(zip(access_token._fields, access_token))

            # Identify the user
            identity = self._handshaker().identify(access_token)
            session['mwoauth_identity'] = identity

            # Redirect to wherever we're supposed to go
            if next_session_key in session:
                return redirect(url_for(session[next_session_key]))
            else:
                return redirect(url_for(self.default_next))

        @self.bp.route("/mwoauth/identify/")
        @authorized
        def mwoauth_identify():
            """
            Returns user information if authenticated
            """
            return jsonify(session['mwoauth_identity'])

        @self.bp.route("/mwoauth/logout/")
        def mwoauth_logout():
            """
            Deletes the local session.
            """
            session.pop('mwoauth_access_token', None)
            session.pop('mwoauth_identity', None)

            if 'next' in request.args:
                return redirect(url_for(request.args.get('next')))
            else:
                return self.render_logout()

    def _handshaker(self):
        if not self.handshaker:
            full_callback = urljoin(
                request.url_root, url_for("mwoauth.mwoauth_callback"))
            print(full_callback)
            self.handshaker = Handshaker(
                self.host, self.consumer_token, user_agent=self.user_agent,
                callback=full_callback)

        return self.handshaker

    @staticmethod
    def identify():
        return session.get('mwoauth_identity')

    def mwapi_session(self, *args, **kwargs):
        """
        Creates :class:`mwapi.Session` that is authorized for the current
        user.

        `args` and `kwargs` are passed directly to :class:`mwapi.Session`
        """
        import mwapi
        auth1 = self.generate_auth()
        return mwapi.Session(*args, **kwargs, user_agent=self.user_agent,
                             auth=auth1)

    def requests_session(self, *args, **kwargs):
        """
        Creates :class:`requests.Session` that is authorized for the current
        user.

        `args` and `kwargs` are passed directly to :class:`requests.Session`
        """
        import requests
        auth1 = self.generate_auth()
        return requests.Session(*args, **kwargs, auth=auth1)

    def generate_auth(self):
        if 'mwoauth_access_token' in session:
            access_token = AccessToken(**session['mwoauth_access_token'])
            auth1 = OAuth1(self.consumer_token.key,
                           client_secret=self.consumer_token.secret,
                           resource_owner_key=access_token.key,
                           resource_owner_secret=access_token.secret)
            return auth1
        else:
            raise OAuthException(
                "Cannot generate auth.  User has not authorized.")


def authorized(route):
    """
    Wraps a flask route. Ensures that the user has authorized via OAuth or
    redirects the user to the authorization endpoint with a delayed redirect
    back to the originating endpoint.
    """
    @wraps(route)
    def authorized_route(*args, **kwargs):
        if 'mwoauth_access_token' in session:
            return route(*args, **kwargs)
        else:
            return redirect(
                url_for('mwoauth.mwoauth_initiate') +
                "?next=" + request.endpoint)

    return authorized_route


def generic_logout():
    return "Logged out"


def generic_identify(identity):
    return jsonify(identity)


def generic_error(message, status):
    return '<span style="color: red;">' + message + '</span>', status


def encode_token(token):
    return dict(zip(token._fields, token))


def _str(val):
    """
    Ensures that the val is the default str() type for python2 or 3
    """
    if str == bytes:
        if isinstance(val, str):
            return val
        else:
            return str(val)
    else:
        if isinstance(val, str):
            return val
        else:
            return str(val, 'ascii')
