MediaWiki OAuth Library
=======================

This library provides a simple means to performing an OAuth handshake with a MediaWiki installation with the `OAuth Extension <https://www.mediawiki.org/wiki/Extension:OAuth>`_.

Usage
-----

.. code-block:: python

	import mwoauth
	from six.moves import input # For compatibility between python 2 and 3
	
	# Construct handshaker
	handshaker = mwoauth.Handshaker("https://en.wikipedia.org/w/index.php", 
	                                mwoauth.Consumer("<key>", "<secret>"))
	
	# Step 1: Initialize
	redirect, resource_owner = handshaker.initiate()
	
	# Step 2: Authorize
	print("Point your browser to: %s" % redirect) # 
	response_qs = input("Response query string: ")
	
	# Step 3: Complete
	authorized_resource_owner = handshaker.complete(resource_owner, response_qs)
	
	# Step 4: Identify (optional)
	print(handshaker.identify(authorized_resource_owner))

