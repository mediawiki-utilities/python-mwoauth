import json
import sys

from mwoauth import ConsumerToken, complete, identify, initiate

sys.path.insert(0, ".")

try:
    creds_doc = json.load(open("credentials.do_not_commit.json"))
    consumer_key = creds_doc['consumer_key']
    consumer_secret = creds_doc['consumer_secret']
except FileNotFoundError:
    print('Couldn\'t find "credentials.do_not_commit.json". ' +
          'Please manually input credentials.')
    consumer_key = input('Consumer key: ')
    consumer_secret = input('Consumer secret: ')

consumer_token = ConsumerToken(consumer_key, consumer_secret)

mw_uri = "https://en.wikipedia.org/w/index.php"

# Step 1: Initialize -- ask MediaWiki for a temporary key/secret for user
redirect, request_token = initiate(mw_uri, consumer_token)

# Step 2: Authorize -- send user to MediaWiki to confirm authorization
print("Point your browser to: %s" % redirect)  #
response_qs = input("Response query string: ")

# Step 3: Complete -- obtain authorized key/secret for "resource owner"
access_token = complete(mw_uri, consumer_token, request_token, response_qs)
print(str(access_token))

# Step 4: Identify -- (optional) get identifying information about the user
identity = identify(mw_uri, consumer_token, access_token)
print("Identified as {username} (id={sub}).".format(**identity))
