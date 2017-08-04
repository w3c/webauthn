#!/bin/bash

if [ ! -x bikeshed/bikeshed.py ]; then
  echo "Precondition failure: expecting a bikeshed installation in ./bikeshed/"
  exit 1
fi

bikeshed/bikeshed.py update
cp -a bikeshed/bikeshed/spec-data/* .spec-data/

echo "Now be sure to run:"
echo " git add .spec-data/"
echo ""
