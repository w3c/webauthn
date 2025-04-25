Scripts for generating WebAuthn test vectors
===

This directory hosts scripts for generating test vectors to include in the Web Authentication spec.


Usage
---

Run the script using the [Poetry](https://python-poetry.org/) build tool:

```sh
$ poetry install
$ poetry run python webauthn-prf-test-vectors.py
```

Then paste the script output into the relevant part of `index.bs`.
