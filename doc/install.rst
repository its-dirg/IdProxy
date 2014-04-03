.. _Install:

Install
=======

IdProxy is at experimental stage and therefore it has some dependencies to the head versions of other projects.


Quick install
-------------
The fastes way to install IdProxy is to use Yais. Yais is only supported by debian based systems, so for all other systems you have to use the manual approach.

First install yais: ::

    sudo –u dirgadmin git clone https://github.com/its-dirg/yais
    cd yais
    sudo python setup.py install

Now you can use yais to install various softwares from DIRG. ::

    ./yaisLinux.sh /[..]/projects

You have to point out the full path to your install directory, relative path do not work with Yais, and you may NOT end the path with a slash.

You will be asked to answer some quistions about what programs you want to install. You only need to answer Y to the IdPproxy question. ::

    Do you want to install IdPproxy (Y/n):

Beware that after you have choosen the software you want to install you will get more questions about the dependencies that will be installed with apt-get. To be sure that everything works you have to install all the dependencies.

When everything has been installed you will be asked to configure pysaml example IdP and SP. Answer no to this question unless you want to setup a test IdP and SP.


Manual install
--------------
First install the following for your OS.

#. Setuptools
#. Swig
#. M2Crypto
#. Xmlsec
#. PyCrypto version 2.6.1 or later.
    Can be installed with easy_install for some systems. Just make sure you get version 2.6.1. ::

        sudo easy_install pycrypto

    To verify version use pip freeze or to really be sure pkg_resources. ::

    pip freeze | grep pycrypto
    pycrypto==2.6.1

    python
    >>>> import pkg_resources
    >>>> pkg_resources.get_distribution("pycrypto").version
    '2.6.1'

#. pyOpenSSL


The rest can be installed with easy_install, pip or get from github: ::

    sudo easy_install pip
    sudo easy_install mako
    sudo pip install python-ldap
    sudo easy_install repoze.who
    sudo easy_install ElementTree
    git clone https://github.com/rohe/pyjwkest
    cd pyjwkest
    sudo python setup.py install
    git clone https://github.com/rohe/pysaml2
    cd pysaml2
    sudo python setup.py install
    git clone https://github.com/rohe/pyoidc
    cd pyoidc
    sudo python setup.py install
    git clone https://github.com/its-dirg/dirg-util
    cd dirg-util
    sudo python setup.py install
    git clone https://github.com/HaToHo/pyYubitool
    cd pyYubitool
    sudo python setup.py install
    git clone https://github.com/its-dirg/IdProxy
    cd IdProxy
    sudo python setup.py install

