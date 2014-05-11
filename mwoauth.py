import requests, time
from requests_oauthlib import OAuth1
from urlparse import parse_qs, urlunparse
from urllib import urlencode
import urllib2
from collections import namedtuple
from calendar import timegm
from datetime import datetime

import jwt

ResourceOwner = namedtuple("ResourceOwner", ['key', 'secret'])
Client = namedtuple("Client", ['key', 'secret'])

class OAuth:
	
	def __init__(self, uri, key, secret):
		self.uri = uri
		self.client = Client(key, secret)
	
	def initiate(self):
		auth = OAuth1(self.client.key, 
		              client_secret=self.client.secret, 
		              callback_uri='oob')
		
		r = requests.post(url=self.uri,
		                  params={'title': "Special:OAuth/initiate"},
		                  auth=auth)
		
		credentials = parse_qs(r.content)
		resource_owner = ResourceOwner(
			credentials.get('oauth_token')[0],
			credentials.get('oauth_token_secret')[0]
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
		callback_data = parse_qs(response_qs)
		
		# TODO probably not assert
		# Handle lack of oauth_token
		# etc. 
		assert resource_owner.key == callback_data.get("oauth_token")[0]
		
		verifier = callback_data.get("oauth_verifier")[0]
		
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
			credentials.get('oauth_token')[0],
			credentials.get('oauth_token_secret')[0]
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
		iss = urllib2.urlparse.urlparse(identify_token['iss']).netloc
		mw_domain = urllib2.urlparse.urlparse(self.uri).netloc
		if iss != mw_domain:
			raise Exception('JSON Web Token Validation Problem, iss')
		
		# Verify we are the intended audience (
		if identify_token['aud'] != self.client.key:
			raise Exception('JSON Web Token Validation Problem, aud')
		
		# Verify we are within the time limits of the token.
		# Issued at (iat) should be in the past
		#now = int(time.time())
		now = timegm(datetime.utcnow().utctimetuple())
		if not int(identify_token['iat']) <= now:
			raise Exception('JSON Web Token Validation Problem, iat')
		
		# Expiration (exp) should be in the future
		if not int(identify_token['exp']) >= now:
			raise Exception('JSON Web Token Validation Problem, exp')
		
		# Verify we haven't seen this nonce before,
		# which would indicate a replay attack
		# TODO: implement nonce but this is not high priority
		#if identify_token['nonce'] != <<original request nonce>>
			#raise Exception('JSON Web Token Validation Problem, nonce')
		
		return identify_token
		
