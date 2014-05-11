MediaWiki OAuth Library
=======================

This library provides a simple means to performing an OAuth handshake with a MediaWiki installation with the `OAuth Extension <https://www.mediawiki.org/wiki/Extension:OAuth>`_.

Usage
-----

.. code-block:: python

    import mwoauth
    oauth = mwoauth.OAuth(
        "https://en.wikipedia.org/w/index.php", 
        "<consumer key>", 
        "<consumer secret>"
    )
    redirect, resource_owner = oauth.initiate()
    print("Go to: %s" % redirect)
    
    auth = oauth.complete(resource_owner, raw_input("response_qs: "))
    
    print oauth.identify(auth)

