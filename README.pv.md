# WebAuthn protocol verification using Proverif

ProVerif Web Authentication Formal Model: webauthn.pv 
   based on webauthn-basic.pv by Iness Ben Guirat
   Paper: https://dl.acm.org/doi/10.1145/3190619.3190640 (by Iness Ben Guirat and Harry Halpin)
   Slides: https://cps-vo.org/node/48511
   github: https://github.com/hhalpin/weauthn-model
   
   See the [Paper] section 5.2 for a detailed description of the original model
   
   MANUAL: The proverif manual is here: https://prosecco.gforge.inria.fr/personal/bblanche/proverif/manual.pdf

`webauthn.pv` models a registration of a WebAuthn user credential with a server (aka Relying Party) and then models subsequent authentication using that registered credential.



## STATUS

This is WORK IN PROGRESS by Jeff Hodges <jdhodges@google.com> as of Aug-2021.


## NOTES

This directory uses the C Preprocessor to modularize ProVerif models (this
is why `run_proverif.sh` is used rather than invoking `proverif` directly).

Specifically, `webauthn.pv` relies upon `crypto.pvl` and `named_tuples.pvl`.

These pvl ("Proverif library") files were obtained from:

  `//google3/cloud/security/virtsec/proverif_rg/seems_legit/`  ..and..

  `//google3/cloud/security/virtsec/proverif_rg/ekep/`


`crypto.pvl` models sophisticated signature proofs based on the recent "Seems Legit" 
paper <https://eprint.iacr.org/2019/779>, see `go/seems-legit-proverif` for details.

`named_tuples.pvl` very cleverly uses the C-preprocessor to make it easy to model 
nested datastructures in Proverif.  `webauthn.pv` uses this liberally to create a 
fine-grained model.

See also: ProVerif Reading Group `//google3/cloud/security/virtsec/proverif_rg/`


## Running Proverif

To run a file in ProVerif, use the script `run_proverif.sh`. This script assumes
that ProVerif is installed on the local machine. The typical usage is:

```bash
$ ./run_proverif.sh webauthn.pv
```

NOTE: You can only run `.pv` files, and not `.pvl` (library) files. Also, 
      `run_proverif.sh` generates colorized output which looks nice in a
      terminal but is lousy to use when captured in a file and examined in 
      an editor (see the next section).


### Running Proverif with no color ouput

`run_proverif.sh`'s standard output is colorized. If you wish to generate output
without colorization, e.g., for examining the output in an editor (doing so can be 
useful for groveling thru the output in order to figure out just what Proverif did
to find an attack) then run Proverif like so:

```bash
$ ./run_proverif-no-color.sh webauthn.pv > some.output.file.name.txt
```


### Debugging syntax errors

If the ProVerif script has a syntax error, the output will refer to a line in
one of the generated files. The temporary files will be automatically cleaned up
after the script finishes. To disable this automatic cleanup, set the
environment variable `PROVERIF_NO_CLEANUP`. For example:

```bash
$ PROVERIF_NO_CLEANUP=1 ./run_proverif.sh webauthn.pv
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

