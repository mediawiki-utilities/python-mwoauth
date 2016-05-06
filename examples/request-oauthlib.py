import requests
from mwoauth import ConsumerToken, Handshaker
from requests_oauthlib import OAuth1

from six.moves import input  # For compatibility between python 2 and 3

import sys;sys.path.insert(0, ".")
import config  # You'll need to provide this

consumer_token = ConsumerToken(config.consumer_key, config.consumer_secret)

# Construct handshaker with wiki URI and consumer
handshaker = Handshaker("https://en.wikipedia.org/w/index.php",
                        consumer_token)

# Step 1: Initialize -- ask MediaWiki for a temporary key/secret for user
redirect, request_token = handshaker.initiate()

# Step 2: Authorize -- send user to MediaWiki to confirm authorization
print("Point your browser to: %s" % redirect)  #
response_qs = input("Response query string: ")

# Step 3: Complete -- obtain authorized key/secret for "resource owner"
access_token = handshaker.complete(request_token, response_qs)

# Construct an auth object with the consumer and access tokens
auth1 = OAuth1(consumer_token.key,
               client_secret=consumer_token.secret,
               resource_owner_key=access_token.key,
               resource_owner_secret=access_token.secret)

# Now, accessing the API on behalf of a user
print("Reading top 10 watchlist items")
response = requests.get(
    "https://en.wikipedia.org/w/api.php",
    params={
        'action': "query",
        'list': "watchlist",
        'wllimit': 10,
        'wlprop': "title|comment",
        'format': "json"
    },
    auth=auth1
)
doc = response.json()
if 'error' in doc:
    print(doc['error']['code'], doc['error']['info'])
else:
    for item in ['query']['watchlist']:
        print("{title}\t{comment}".format(**item))
