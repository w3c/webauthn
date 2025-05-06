#!/bin/bash

# Exit on error
set -e


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

if [[ "$1" == "--check" ]]; then
  if ! git diff --exit-code --stat -- ../index.bs; then
    echo "Cannot check if test vectors are up to date. Please commit or revert changes to index.bs first."
    exit 1
  fi
fi

poetry install
inject webauthn-test-vectors.py
inject webauthn-prf-test-vectors.py

if [[ "$1" == "--check" ]]; then
  if git diff --exit-code --stat -- ../index.bs; then
    echo "Generated content is up to date."
  else
    echo "Generated content is up not to date. Please run test-vectors/inject-generated-content.sh and commit the results."
    exit 1
  fi
fi
