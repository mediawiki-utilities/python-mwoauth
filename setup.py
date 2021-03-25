import os

from setuptools import find_packages, setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


about_path = os.path.join(os.path.dirname(__file__), "mwoauth/about.py")
exec(compile(open(about_path).read(), about_path, "exec"))


setup(
    name=__name__,  # noqa
    version=__version__,  # noqa
    author=__author__,  # noqa
    author_email=__author_email__,  # noqa
    description=__description__,  # noqa
    url=__url__,  # noqa
    license=__license__,  # noqa
    packages=find_packages(),
    long_description=read('README.rst'),
    install_requires=[
        'PyJWT>=1.0.1',
        'oauthlib',
        'requests',
        'requests-oauthlib',
        'six'
    ],
    extras_require={
        'flask': ['flask'],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
