from collections import namedtuple
import jwt
import requests
from requests_oauthlib import OAuth1
import six
import time
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



ResourceOwner = namedtuple("ResourceOwner", ['key', 'secret'])
Client = namedtuple("Client", ['key', 'secret'])

def safe_parse_qs(qs):
	params = parse_qs(qs)
	safe_params = {}
	for key in params:
		values = params[key]
		safe_params[six.b(key)] = [six.b(v) for v in values]
	
	return safe_params

class OAuth:
	"""
	Constructs a client for managing OAuth handshakes from a base URI
	(ending in "/w/index.php") and a "comsumer/client" key and secret.
	
	:Parameters:
		uri : `str`
			The base URI of the wiki to authenticate with
		key : `str`
			The "consumer/client" key (provided by MediaWiki)
		secret : `str`
			The "consumer/client" secret (provided by MediaWiki)
	"""
	def __init__(self, uri, key, secret):
		self.uri = uri
		self.client = Client(key, secret)
	
	def initiate(self):
		"""
		Initiates an oauth handshake.
		
		:Returns:
			redirect_url : str
				A URL to send the user ("resource owner")
			resource_owner : `ResourceOwner`
				An object containing resource owner information (pass this to complete)
		"""
		auth = OAuth1(self.client.key, 
		              client_secret=self.client.secret, 
		              callback_uri='oob')
		
		r = requests.post(url=self.uri,
		                  params={'title': "Special:OAuth/initiate"},
		                  auth=auth)
		print(r.content)
		credentials = parse_qs(r.content)
		
		resource_owner = ResourceOwner(
			credentials.get(six.b('oauth_token'))[0],
			credentials.get(six.b('oauth_token_secret'))[0]
		)
		
		return (
			(
				self.uri + "?" + 
				urlencode({'title': "Special:OAuth/authorize",
				           'oauth_token': resource_owner.key,
				           'oauth_consumer_key': self.client.key})
			),
			resource_owner
		)
		
	def complete(self, resource_owner, response_qs):
		"""
		Completes an oauth handshake
		"""
		callback_data = safe_parse_qs(response_qs)
		
		# TODO probably not assert
		# Handle lack of oauth_token
		# etc. 
		assert resource_owner.key == callback_data.get(six.b("oauth_token"))[0]
		
		verifier = callback_data.get(six.b("oauth_verifier"))[0]
		
		auth = OAuth1(self.client.key, 
		              client_secret=self.client.secret,
		              resource_owner_key=resource_owner.key,
		              resource_owner_secret=resource_owner.secret,
		              verifier=verifier)
		
		r = requests.post(url=self.uri,
		                  params={'title': "Special:OAuth/token"},
		                  auth=auth)
		
		credentials = parse_qs(r.content)
		authorized_owner = ResourceOwner(
			credentials.get(six.b('oauth_token'))[0],
			credentials.get(six.b('oauth_token_secret'))[0]
		)
		
		return OAuth1(self.client.key,
		              client_secret=self.client.secret, 
		              resource_owner_key=authorized_owner.key, 
		              resource_owner_secret=authorized_owner.secret)
	
	
	def identify(self, auth):
		r = requests.post(url=self.uri,
		                  params={'title': "Special:OAuth/identify"},
		                  auth=auth)
		
		# TODO: Handle jwt.DecodeError
		identify_token, signing_input, header, signature = jwt.load(r.content)
		
		# Ensure no downgrade in authentication
		assert header['alg'] == "HS256"
		
		 # TODO: Handle jwt.DecodeError
		jwt.verify_signature(identify_token, signing_input, header, signature,
		                     self.client.secret, False)
		
		# Verify the issuer is who we expect (server sends $wgCanonicalServer)
		iss = urlparse(identify_token['iss']).netloc
		mw_domain = urlparse(self.uri).netloc
		if iss != mw_domain:
			raise Exception('JSON Web Token Validation Problem, iss')
		
		# Verify we are the intended audience (
		if identify_token['aud'] != self.client.key:
			raise Exception('JSON Web Token Validation Problem, aud')
		
		# Verify we are within the time limits of the token.
		# Issued at (iat) should be in the past
		now = int(time.time())
		if not int(identify_token['iat']) <= now:
			raise Exception('JSON Web Token Validation Problem, iat')
		
		# Expiration (exp) should be in the future
		if not int(identify_token['exp']) >= now:
			raise Exception('JSON Web Token Validation Problem, exp')

		# Verify that the nonce matches our request one,
		# to avoid a replay attack
		request_nonce = re.search(r'oauth_nonce="(.*?)"',
			r.request.headers['Authorization']).group(1)
		if identify_token['nonce'] != request_nonce:
			raise Exception('JSON Web Token Validation Problem, nonce')
		
		return identify_token
		
