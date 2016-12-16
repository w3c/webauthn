
# Web Authentication Specification

This is the repository for the W3C WebAuthn Working Group, producing the draft **"Web Authentication"** specification.

* [The editor's copy is available at https://w3c.github.io/webauthn/](https://w3c.github.io/webauthn/), or in the [`gh-pages` branch of this repository](https://github.com/w3c/webauthn/blob/gh-pages/index.html).
  - The current *offically-published working-draft snapshot* [is here: https://www.w3.org/TR/webauthn/](https://www.w3.org/TR/webauthn/).
* [The build history is available at Travis-CI.org](https://travis-ci.org/w3c/webauthn/builds)
* [W3C WebAuthn Blog](https://www.w3.org/blog/webauthn/)
* [Web platform tests repository](https://github.com/w3c/web-platform-tests/tree/master/webauthn)

# Contributing

To materially contribute to this specification, you must meet the requiements outlined in [CONTRIBUTING.md](/CONTRIBUTING.md). Also, before submitting feedback, please familiarize yourself with [our current issues list](https://github.com/w3c/webauthn/issues) and review the [mailing list discussion](https://lists.w3.org/Archives/Public/public-webauthn/).

# Building the Draft

Formatted HTML for the draft can be built using `bikeshed` (see below for instructions for `bikeshed` installation):

```
$ bikeshed spec
```

You may also want to use the `watch` functionality to automatically regenerate as you make changes:

```
$ bikeshed watch
```

# Bikeshed Installation and Setup

You will need to have the Python tools `pygments` and `bikeshed` to build the draft. Pygments can be obtained via `pip`, but Bikeshed will need to be downloaded with `git`:

```
git clone --depth=1 --branch=master https://github.com/tabatkins/bikeshed.git ./bikeshed
pip install pygments
pip install --editable ./bikeshed
cp -R .spec-data/* ./bikeshed/bikeshed/spec-data
```

# Continuous Integration & Branches

This repository uses `.deploy-output.sh` to generate the Editor's Draft on the `gh-pages` branch upon every merge to `master`. In order to prevent failed merges during continuous integration, the formatted Editor's Draft should not be checked in to `master`, and it is in the `.gitignore` file.

# Creating a new Working Draft

To build a new WD and upload it to the W3C publishing system:
- Make sure Bikeshed is installed locally
- Edit the Bikeshed metadata to change the status from ED to WD (do not commit this change)
- Build and upload the new draft with
```
bikeshed echidna --u USERNAME --p PASSWORD --d DECISION_URL
```

This will create a tarball of the HTML and images, and upload to Echidna. Status of the request can be tracked through the W3C API [as described in the Echidna documentation](https://github.com/w3c/echidna/wiki/How-to-use-Echidna). Note that on Windows, this will give an error about failing to delete a temporary file because it is in use by a different process. This error is harmless; it happens after the submission has completed.

Overall info on echidna is here: https://github.com/w3c/echidna/wiki and here https://labs.w3.org/echidna/.
