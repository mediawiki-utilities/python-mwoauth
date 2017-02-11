.. MediaWiki OAuth documentation master file, created by
   sphinx-quickstart on Wed May 14 18:52:32 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

MediaWiki OAuth Library Documentation
=====================================

``mwoauth`` is an open licensed (MIT) library designed to provide a simple means to performing an OAuth handshake with a MediaWiki installation with the `OAuth Extension <https://www.mediawiki.org/wiki/Extension:OAuth>`_ installed.

**Compatible with python 2.7 and 3.x**

**Install with pip:** ``pip install mwoauth``

There are two ways to use this library:

* :class:`~mwoauth.Handshaker` -- an object oriented handshake manager
* A set of stateless functions: :py:func:`~moauth.intitiate`, :py:func:`~moauth.complete` and :py:func:`~moauth.identify`.

Both of strategies make use of the same set of tokens (:class:`~mwoauth.ConsumerToken`, :class:`~mwoauth.RequestToken` and :class:`~mwoauth.AccessToken`) and are totally inter-operable (if you like to mixing things up).

There's also a :class:`flask.Blueprint` handler.  See :mod:`mwoauth.flask`.

The OAuth Handshaker
====================

.. automodule:: mwoauth.handshaker

.. autoclass:: mwoauth.Handshaker
   :members:
   :member-order: bysource


Tokens
======

.. automodule:: mwoauth.tokens

.. autoclass:: mwoauth.ConsumerToken
   :members:
   :member-order: bysource

.. autoclass:: mwoauth.RequestToken
   :members:
   :member-order: bysource

.. autoclass:: mwoauth.AccessToken
   :members:
   :member-order: bysource


Stateless functions
===================

.. automodule:: mwoauth.functions

.. autofunction:: mwoauth.initiate

.. autofunction:: mwoauth.complete

.. autofunction:: mwoauth.identify


About
=================
:authors:
	Aaron Halfaker (http://halfaker.info) •
	Filippo Valsorda (https://filippo.io)
:repository:
	`mwoauth @ GitHub <https://github.com/wikimedia/MediaWiki-OAuth>`_
:documentation:
	`mwoauth @ pythonhosted <http://pythonhosted.org/mwoauth>`_

Contributors
============
Pull requests are encouraged!

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
