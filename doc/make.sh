#!/bin/sh
rm idproxy*
sphinx-apidoc -F -o ../doc/ ../src/idproxy
make clean
make html