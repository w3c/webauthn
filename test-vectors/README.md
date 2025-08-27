Scripts for generating WebAuthn test vectors
===

This directory hosts scripts for generating test vectors to include in the Web Authentication spec.


Usage
---

Use the script `inject-generated-content.sh` to generate and inject the content into `../index.bs`:

```sh
$ cd test-vectors
$ ./inject-generated-content.sh
```

If run with `--check`, the script will return a nonzero exit code if it results in any changes to `../index.bs`:

```sh
$ ./inject-generated-content.sh --check
```

Alternatively, you can run the content generation scripts manually:

```sh
$ poetry install
$ poetry run python webauthn-test-vectors.py
$ poetry run python webauthn-prf-test-vectors.py
```

Then paste the script outputs into the respective relevant part of `index.bs`.
