#!/bin/sh
rm -f idproxy*
cd ..
sphinx-apidoc -F -o /doc/ /src/idproxy
cd doc
make clean
make html