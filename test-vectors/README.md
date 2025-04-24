Scripts for generating WebAuthn test vectors
===

This directory hosts scripts for generating test vectors to include in the Web Authentication spec.


Usage
---

Run the scripts using the [Poetry](https://python-poetry.org/) build tool:

```sh
$ poetry install
$ poetry run python webauthn-test-vectors.py
$ poetry run python webauthn-prf-test-vectors.py
```

Then paste the script outputs into the respective relevant part of `index.bs`.
