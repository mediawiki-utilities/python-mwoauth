import json
import os
from builtins import input

import mwoauth
import mwoauth.flask
from flask import Flask, jsonify

app = Flask(__name__)

# Generate a random secret application key
#
# NOTE: this key changes every invocation. In an actual application, the key
# should not change! Otherwise you might get a different secret key for
# different requests, which means you can't read data stored in cookies,
# which in turn breaks OAuth.
#
# So, for an actual application, use app.secret_key = "some long secret key"
# (which you could generate using os.urandom(24))
#
app.secret_key = os.urandom(24)

print("""
NOTE: The callback URL you entered when proposing an OAuth consumer
probably did not match the URL under which you are running this development
server. Your redirect back will therefore fail -- please adapt the URL in
your address bar to http://localhost:5000/oauth-callback?oauth_verifier=...etc
""")

try:
    creds_doc = json.load(open("credentials.do_not_commit.json"))
    consumer_key = creds_doc['consumer_key']
    consumer_secret = creds_doc['consumer_secret']
except FileNotFoundError:
    print('Couldn\'t find "credentials.do_not_commit.json". ' +
          'Please manually input credentials.')
    consumer_key = input('Consumer key: ')
    consumer_secret = input('Consumer secret: ')

consumer_token = mwoauth.ConsumerToken(consumer_key, consumer_secret)
flask_mwoauth = mwoauth.flask.MWOAuth(
    'https://meta.wikimedia.org', consumer_token,
    user_agent="Demo mwoauth.flask server.")
app.register_blueprint(flask_mwoauth.bp)

@app.route("/")
def index():
    return "logged in as: " + \
           repr((flask_mwoauth.identify() or {}).get('username')) + \
           "<br />" + \
           '<a href="mwoauth/initiate">initiate</a> / ' + \
           '<a href="mwoauth/identify">identify</a> / ' + \
           '<a href="my_recent_edits">my_recent_edits</a> / ' + \
           '<a href="mwoauth/logout">logout</a>'


@app.route("/my_recent_edits")
@flask_mwoauth.authorized
def my_recent_edits():
    username = flask_mwoauth.identify()['username']
    enwiki_session = flask_mwoauth.mwapi_session('https://en.wikipedia.org')
    doc = enwiki_session.get(action="query", list="usercontribs",
                             ucuser=username, ucprop="timestamp",
                             format="json")
    return jsonify(doc)

if __name__ == "__main__":
    app.run(debug=True, threaded=True)
