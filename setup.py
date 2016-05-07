import os
from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


def requirements(fname):
    for line in open(os.path.join(os.path.dirname(__file__), fname)):
        yield line.strip()


# Read version from file shared with the module using technique from
# https://python-packaging-user-guide.readthedocs.io/en/latest/single_source_version/
base_dir = os.path.dirname(__file__)
version = {}
with open(os.path.join(base_dir, 'mwoauth', 'version.py')) as fp:
    exec(fp.read(), version)

setup(
    name="mwoauth",
    version=version['__version__'],
    author="Aaron Halfaker / Filippo Valsorda",
    author_email="ahalfaker@wikimedia.org",
    description=("A generic MediaWiki OAuth handshake helper."),
    license="MIT",
    url="https://github.com/halfak/MediaWiki-OAuth",
    packages=find_packages(),
    long_description=read('README.rst'),
    install_requires=[
        'PyJWT>=1.0.1,<2.0.0',
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
