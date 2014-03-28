#!/bin/sh
cd ../
sudo python setup.py install
cd doc
rm -f idproxy*
sphinx-apidoc -F -o ../doc/ ../src/idproxy
make clean
make html