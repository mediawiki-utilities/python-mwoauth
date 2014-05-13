MediaWiki OAuth Library
=======================

This library provides a simple means to performing an OAuth handshake with a MediaWiki installation with the `OAuth Extension <https://www.mediawiki.org/wiki/Extension:OAuth>`_.

Usage
-----

.. code-block:: python

	import mwoauth
	from six.moves import input # For compatibility between python 2 and 3
	
	# Consruct a "consumer" from the key/secret provided by MediaWiki
	import config
	consumer = mwoauth.Consumer(config.consumer_key, config.consumer_secret)
	
	# Construct handshaker with wiki URI and consumer
	handshaker = mwoauth.Handshaker("https://en.wikipedia.org/w/index.php",
	                                consumer)
	
	# Step 1: Initialize -- ask MediaWiki for a temporary key/secret for user
	redirect, resource_owner = handshaker.initiate()
	
	# Step 2: Authorize -- send user to MediaWiki to confirm authorization
	print("Point your browser to: %s" % redirect) # 
	response_qs = input("Response query string: ")
	
	# Step 3: Complete -- obtain authorized key/secret for "resource owner"
	authorized_resource_owner = handshaker.complete(resource_owner, response_qs)
	
	# Step 4: Identify -- (optional) get identifying information about the user
	identity = handshaker.identify(authorized_resource_owner)
	
	# Print results
	print("Identified as {username}.".format(**identity))
	print("key={0}".format(authorized_resource_owner.key))
	print("secret={0}".format(authorized_resource_owner.secret))

