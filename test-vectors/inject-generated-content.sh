#!/bin/sh

# Exit on error
set -e

# Echo commands
set -x

poetry install


inject() {
  SCRIPT="$1"
  BLOCK_TAG="GENERATED CONTENT: Use test-vectors\/${SCRIPT}"

  # Print everything before the generated content block
  sed "/<!-- ${BLOCK_TAG} -->/,\$d" < ../index.bs > index.bs.new

  # Print the generated content block
  poetry run python "${SCRIPT}" >> index.bs.new

  # Print everything after the generated content block
  sed "0,/<!-- END ${BLOCK_TAG} -->/d" < ../index.bs >> index.bs.new

  mv index.bs.new ../index.bs
}

inject webauthn-test-vectors.py
inject webauthn-prf-test-vectors.py
