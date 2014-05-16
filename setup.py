import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

def requirements(fname):
	for line in open(os.path.join(os.path.dirname(__file__), fname)):
		yield line.strip()

setup(
	name = "mwoauth",
	version = read('VERSION').strip(),
	author = "Aaron Halfaker / Filippo Valsorda",
	author_email = "ahalfaker@wikimedia.org",
	description = ("A generic MediaWiki OAuth handshake helper."),
	license = "MIT",
	url = "https://github.com/halfak/MediaWiki-OAuth",
	py_modules = ['mwoauth'],
	long_description = read('README.rst'),
	install_requires = [
		'PyJWT',
		'oauthlib',
		'requests',
		'requests-oauthlib',
		'six'
	],
	classifiers=[
		"Development Status :: 4 - Beta",
		"Topic :: Security",
		"License :: OSI Approved :: MIT License",
		"Topic :: Software Development :: Libraries :: Python Modules"
	],
)
