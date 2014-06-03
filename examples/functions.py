import sys;sys.path.insert(0, ".")
from mwoauth import ConsumerToken, initiate, complete, identify
from six.moves import input # For compatibility between python 2 and 3

# Consruct a "consumer" from the key/secret provided by MediaWiki
import config # You'll need to provide this
consumer_token = ConsumerToken(config.consumer_key, config.consumer_secret)
mw_uri = "https://en.wikipedia.org/w/index.php"

# Step 1: Initialize -- ask MediaWiki for a temporary key/secret for user
redirect, request_token = initiate(mw_uri, consumer_token)

# Step 2: Authorize -- send user to MediaWiki to confirm authorization
print("Point your browser to: %s" % redirect) # 
response_qs = input("Response query string: ")

# Step 3: Complete -- obtain authorized key/secret for "resource owner"
access_token = complete(mw_uri, consumer_token, request_token, response_qs)
print(str(access_token))

# Step 4: Identify -- (optional) get identifying information about the user
identity = identify(mw_uri, consumer_token, access_token)
print("Identified as {username} (id={sub}).".format(**identity))
