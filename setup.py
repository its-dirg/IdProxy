# coding=utf-8
from setuptools import setup

setup(
    name="IdProxy",
    version="0.1",
    description='Proxy for SAML, OpenID connect, OAuth.',
    author = "Hans Hörberg",
    author_email = "hans.horberg@umu.se",
    license="Apache 2.0",
    packages=["idproxy", "idproxy/client", "idproxy/client/sp",
              "idproxy/provider", "idproxy/provider/idp", "idproxy/provider/idp/auth",
              "idproxy/provider/op", "idproxy/util"],
    package_dir = {"": "src"},
    classifiers = ["Development Status :: 0.1 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires = ['oic', 'requests', "pycrypto",
                        "cherrypy==3.2.4", "mako", "pyjwkest", "beaker", "argparse"],

    zip_safe=False,
)
