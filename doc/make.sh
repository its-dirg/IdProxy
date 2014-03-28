#!/bin/sh
rm - f idproxy*
sphinx-apidoc -F -o ../doc/ ../src/idproxy
make clean
make html