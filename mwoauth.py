"""Provides a collection of utilities for easily working with MediaWiki's 
OAuth1.0a implementation."""
from collections import namedtuple
import jwt, requests, time, six
from requests_oauthlib import OAuth1
import six

try:
	from urlparse import parse_qs
except ImportError:
	from urllib.parse import parse_qs

try:
	from urllib import urlencode
except ImportError:
	from urllib.parse import urlencode

try:
	from urlparse import urlparse
except ImportError:
	from urllib.parse import urlparse


Token = namedtuple("Token", ['key', 'secret'])

class ConsumerToken(Token):
	"""
	Represents a consumer (you).  This key/secrets pair is provided by MediaWiki
	when you register an OAuth consumer (see 
	``Special:OAuthConsumerRegistration``). Note that Extension:OAuth must be 
	installed in order in order for ``Special:OAuthConsumerRegistration`` to 
	appear. 
	
	:Parameters:
		key : `str`
			A hex string identifying the user
		secret : `str`
			A hex string used to sign communications
	"""
	pass

class RequestToken(Token):
	"""
	Represents a request for access during authorization.  This key/secret pair 
	is provided by MediaWiki via ``Special:OAuth/initiate``.  
	Once the user authorize you, this token can be traded for an `AccessToken`
	via `complete()`.
	
	:Parameters:
		key : `str`
			A hex string identifying the user
		secret : `str`
			A hex string used to sign communications
	"""
	pass

class AccessToken(Token): 
	"""
	Represents an authorized user.  This key and secret is provided by MediaWiki
	via ``Special:OAuth/complete`` and later used to show MediaWiki evidence of
	authorization.
	
	:Parameters:
		key : `str`
			A hex string identifying the user
		secret : `str`
			A hex string used to sign communications
	"""
	pass

def safe_parse_qs(qs):
	params = parse_qs(qs)
	
	if params != None:
		safe_params = {}
		for key in params:
			values = params[key]
			safe_params[six.b(key)] = [six.b(v) for v in values]
		
		return safe_params
	

def initiate(mw_uri, consumer_token):
	"""
	Initiates an oauth handshake with MediaWik.
	
	:Parameters:
		mw_uri : `str`
			The base URI of the MediaWiki installation.  Note that the URI 
			should end in ``"index.php"``. 
		consumer_token : :class:`~mwoauth.ConsumerToken`
			A token representing you, the consumer.  Provided by MediaWiki via
			``Special:OAuthConsumerRegistration``.
	
	:Returns:
		A `tuple` of two values:
		
		* a MediaWiki URL to direct the user to
		* a :class:`~mwoauth.RequestToken` representing a request for access
		
	
	"""
	auth = OAuth1(consumer_token.key,
				  client_secret=consumer_token.secret,
				  callback_uri='oob')
	
	r = requests.post(url=mw_uri,
					  params={'title': "Special:OAuth/initiate"},
					  auth=auth)
	
	credentials = parse_qs(r.content)
	
	if credentials == None:
		raise Exception("Expected x-www-form-urlencoded response from " + \
		                "MediaWiki, but got some HTML formatted error instead.")
	
	request_token = RequestToken(
		credentials.get(six.b('oauth_token'))[0],
		credentials.get(six.b('oauth_token_secret'))[0]
	)
	
	return (
		mw_uri + "?" + urlencode({'title': "Special:OAuth/authorize",
		                       'oauth_token': request_token.key,
		                       'oauth_consumer_key': consumer_token.key}),
		request_token
	)

def complete(mw_uri, consumer_token, request_token, response_qs):
	"""
	Completes an OAuth handshake with MediaWiki by exchanging an 
	
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
	
	callback_data = safe_parse_qs(response_qs)
	
	# Check if the query string references the right temp resource owner key
	request_token_key = callback_data.get(six.b("oauth_token"))[0]
	if not request_token.key == request_token_key:
		raise Exception("Unexpect request token key " + \
		                "{0}, expected {1}.".format(request_token_key,
		                                            request_token.key))
	
	# Get the verifier token
	verifier = callback_data.get(six.b("oauth_verifier"))[0]
	
	# Construct a new auth with the verifier
	auth = OAuth1(consumer_token.key, 
				  client_secret=consumer_token.secret,
				  resource_owner_key=request_token.key,
				  resource_owner_secret=request_token.secret,
				  verifier=verifier)
	
	# Send the verifier and ask for an authorized resource owner key/secret
	r = requests.post(url=mw_uri,
					  params={'title': "Special:OAuth/token"},
					  auth=auth)
	
	# Parse response and construct an authorized resource owner
	credentials = parse_qs(r.content)
	
	if credentials == None:
		raise Exception("Expected x-www-form-urlencoded response, " + 
		                "but got some else instead: {0}".format(r.content))
	
	access_token = AccessToken(
		credentials.get(six.b('oauth_token'))[0],
		credentials.get(six.b('oauth_token_secret'))[0]
	)
	
	return access_token

def identify(mw_uri, consumer_token, access_token, leeway=10.0):
	"""
	Gather's identifying information about a user via an authorized token.
	
	:Parameters:
		mw_uri : `str`
			The base URI of the MediaWiki installation.  Note that the URI 
			should end in ``"index.php"``. 
		consumer_token : :class:`~mwoauth.ConsumerToken`
			A token representing you, the consumer.
		access_token : :class:`~mwoauth.AccessToken`
			A token representing an authorized user.  Obtained from `complete()`
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
	                  auth=auth)
	
	# Decode json & stuff
	try:
		identity, signing_input, header, signature = jwt.load(r.content)
	except jwt.DecodeError as e:
		raise Exception("An error occurred while trying to read json " + \
		                "content: {0}".format(e))
	
	# Ensure no downgrade in authentication
	if not header['alg'] == "HS256":
		raise Exception("Unexpected algorithm used for authentication " + \
		                "{0}, expected {1}".format("HS256", header['alg']))
	
	
	# Check signature
	try:
		jwt.verify_signature(identity, signing_input, header, signature,
		                     consumer_token.secret, False)
	except jwt.DecodeError as e:
		raise Exception("Could not verify the jwt signature: {0}".format(e))
	
	
	# Verify the issuer is who we expect (server sends $wgCanonicalServer)
	issuer = urlparse(identity['iss']).netloc
	expected_domain = urlparse(mw_uri).netloc
	if not issuer == expected_domain:
		raise Exception("Unexpected issuer " + \
		                "{0}, expected {1}".format(issuer, expected_domain))
	
	
	# Verify we are the intended audience of this response
	audience = identity['aud']
	if not audience == consumer_token.key:
		raise Exception("Unexpected audience " + \
		                "{0}, expected {1}".format(aud, my_domain))
	
	now = time.time()
	
	# Check that the identity was issued in the past.
	issued_at = float(identity['iat'])
	if not now >= (issued_at - leeway):
		raise Exception("Identity issued {0} ".format(issued_at - now) + \
		                "seconds in the future!")
	
	# Check that the identity has not yet expired
	expiration = float(identity['exp'])
	if not now <= expiration:
		raise Exception("Identity expired {0} ".format(expiration - now) + \
		                "seconds ago!")
	
	# Verify we haven't seen this nonce before,
	# which would indicate a replay attack
	# TODO: implement nonce but this is not high priority
	#if identity['nonce'] != <<original request nonce>>
		#raise Exception('JSON Web Token Validation Problem, nonce')
	
	return identity


class Handshaker(object):
	"""
	Constructs a client for managing an OAuth handshake.
	
	:Example: 
		.. code-block:: python
		
			from mwoauth import ConsumerToken, Handshaker
			from six.moves import input # For compatibility between python 2 and 3
			
			# Consruct a "consumer" from the key/secret provided by MediaWiki
			import config
			consumer_token = ConsumerToken(config.consumer_key, config.consumer_secret)
			
			# Construct handshaker with wiki URI and consumer
			handshaker = Handshaker("https://en.wikipedia.org/w/index.php",
			                        consumer_token)
			
			# Step 1: Initialize -- ask MediaWiki for a temporary key/secret for user
			redirect, request_token = handshaker.initiate()
			
			# Step 2: Authorize -- send user to MediaWiki to confirm authorization
			print("Point your browser to: %s" % redirect) # 
			response_qs = input("Response query string: ")
			
			# Step 3: Complete -- obtain authorized key/secret for "resource owner"
			access_token = handshaker.complete(request_token, response_qs)
			print(str(access_token))
			
			# Step 4: Identify -- (optional) get identifying information about the user
			identity = handshaker.identify(access_token)
			print("Identified as {username}.".format(**identity))
	
	:Parameters:
		mw_uri : `str`
			The base URI of the wiki (provider) to authenticate with.  This uri
			should end in ``"index.php"``. 
		consumer_token : :class:`~mwoauth.ConsumerToken`
			A token representing you, the consumer.  Provided by MediaWiki via
			``Special:OAuthConsumerRegistration``.
	"""
	def __init__(self, mw_uri, consumer_token):
		self.mw_uri = mw_uri
		self.consumer_token = consumer_token
	
	def initiate(self):
		"""
		Initiates an OAuth handshake with MediaWiki.
		
		:Returns:
			A `tuple` of two values:
			
			* a MediaWiki URL to direct the user to
			* a :class:`~mwoauth.RequestToken` representing an access request
			
		
		"""
		return initiate(self.mw_uri, self.consumer_token)
		
	def complete(self, request_token, response_qs):
		"""
		Completes an OAuth handshake with MediaWiki by exchanging an 
		
		:Parameters:
			request_token : `RequestToken`
				A temporary token representing the user.  Returned by 
				`initiate()`.
			response_qs : `bytes`
				The query string of the URL that MediaWiki forwards the user 
				back after authorization.
			
		:Returns:
			An :class:`~mwoauth.AccessToken` containing an authorized key/secret 
			pair that can be stored and used by you.
		"""
		return complete(self.mw_uri, self.consumer_token, request_token, response_qs)
	
	def identify(self, access_token, leeway=10.0):
		"""
		Gather's identifying information about a user via an authorized token.
		
		:Parameters:
			access_token : `AccessToken`
				A token representing an authorized user.  Obtained from 
				`complete()`.
			leeway : `int` | `float`
				The number of seconds of leeway to account for when examining a 
				tokens "issued at" timestamp.
			
		:Returns:
			A dictionary containing identity information.
		"""
		return identify(self.mw_uri, self.consumer_token, access_token, 
		                leeway=leeway)
