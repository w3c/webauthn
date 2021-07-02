# WebAuthn protocol verification effort

This directory uses the C Preprocessor to modularize ProVerif models. It also
introduces `*_test.pv` files that do testing in the applied pi calculus by
setting up processes that send out either `Success` or `Failure` bitstrings and
querying ProVerif to see if the adversary can get a `Failure` message. See
`list_test.pv` for an example.

## Running ProVerif

To run a file in ProVerif, use the script `run_proverif.sh`. This script assumes
that ProVerif is installed on the local machine. The typical usage is:

```bash
$ ./run_proverif.sh list_test.pv
```

NOTE: You can only run `.pv` files, and not `.pvl` (library) files.

### Debugging syntax errors

If the ProVerif script has a syntax error, the output will refer to a line in
one of the generated files. The temporary files will be automatically cleaned up
after the script finishes. To disable this automatic cleanup, set the
environment variable `PROVERIF_NO_CLEANUP`. For example:

```bash
$ PROVERIF_NO_CLEANUP=1 ./run_proverif.sh list_test.pv
```

## Running ProVerif Interactively

The `run_proverif.sh` script supports an environment variable
`PROVERIF_INTERACT`. If this variable is set, then `run_proverif.sh` will call
`proverif_interact` on the generated file instead of `proverif`. This brings up
an interactive GUI that allows the user to act as the adversary in a protocol.
For example:

```bash
$ PROVERIF_INTERACT=1 ./run_proverif.sh ekep.pv
```

To facilitate the job of the adversary in interactive mode, the `ekep.pvl` file
conditionally defines helper functions that support generating some of the
messages that would otherwise be tedious and error-prone to type. See the
`ifdef ENABLE_DEBUG_FUNCTIONS` block in `ekep.pvl` for these functions.

The `run_proverif.sh` script always defines `ENABLE_DEBUG_FUNCTIONS` when
`PROVERIF_INTERACT` is set.

