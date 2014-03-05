# coding=utf-8
from distutils.core import setup

setup(
    name="pyOpSamlProxy",
    version="0.1",
    description='Proxy for SAML, OpenID connect, OAuth.',
    author = "Hans Hörberg",
    author_email = "hans.horberg@umu.se",
    license="Apache 2.0",
    packages=[],
    package_dir = {"": "src"},
    classifiers = ["Development Status :: 0.1 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires = ['oic', 'pyoidc', 'requests', "pycrypto",
                        "cherrypy", "mako", "pyjwkest", "beaker"],

    zip_safe=False,
)