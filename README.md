
# Web Authentication Specification

This is the repository for the W3C WebAuthn Working Group, producing the draft **"Web Authentication"** specification.

* [The editor's copy is available at https://w3c.github.io/webauthn/](https://w3c.github.io/webauthn/), or in the [`gh-pages` branch of this repository](https://github.com/w3c/webauthn/blob/gh-pages/index.html).
  - The current *offically-published working-draft snapshot* [is here: https://www.w3.org/TR/webauthn/](https://www.w3.org/TR/webauthn/).
* [The build history is available at Travis-CI.org](https://travis-ci.org/w3c/webauthn/builds)
* [W3C WebAuthn Blog](https://www.w3.org/blog/webauthn/)
* [Web platform tests repository](https://github.com/w3c/web-platform-tests/tree/master/webauthn)

# Contributing

To materially contribute to this specification, you must meet the requirements outlined in [CONTRIBUTING.md](/CONTRIBUTING.md). Also, before submitting feedback, please familiarize yourself with [our current issues list](https://github.com/w3c/webauthn/issues) and review the [mailing list discussion](https://lists.w3.org/Archives/Public/public-webauthn/).

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

Alternatively, you can use the [Vagrant VM with `bikeshed` already installed](vagrant/bikeshed).


# Continuous Integration & Branches

This repository uses `.deploy-output.sh` to generate the Editor's Draft on the `gh-pages` branch upon every merge to `master`. In order to prevent failed merges during continuous integration, the formatted Editor's Draft should not be checked in to `master`, and it is in the `.gitignore` file.

# Creating a new Working Draft

To build a new WD and upload it to the W3C publishing system:
- Register as a W3C member and join the Web Authentication working group. Note down your W3C USERNAME and PASSWORD to use in the command below. If you don't remember either one, please go [here](https://www.w3.org/accounts/recover) to retrieve it.
- Copy the url of the meeting minutes in which the working group decided to publish a new draft as the DECISION_URL to be used below
- Make sure Bikeshed is installed locally (follow the Bikeshed Installation and Setup section above)
- Go into the ./bikeshed directory and use git pull to update Bikeshed.
- Run the following command to update Bikeshed's datafiles: 
```
bikeshed update
```
- Edit the Bikeshed metadata to change the status from ED to WD (do not commit this change)
- Ensure Bikeshed can compile without any error or warning by running through the following command: 
```
bikeshed spec
```
- Build and upload the new draft with
```
bikeshed echidna --u USERNAME --p PASSWORD --d DECISION_URL
```

The command above will create a tarball of the HTML and images, and upload to Echidna, W3C's automated publishing system. The command should return a url, thhrough which you can know whether you successfully publish the draft. Status of the request can also be tracked through the [Mailing List Archive](https://lists.w3.org/Archives/Public/public-tr-notifications/). You can also use W3C API [as described in the Echidna documentation](https://github.com/w3c/echidna/wiki/How-to-use-Echidna). Note that on Windows, this will give an error about failing to delete a temporary file because it is in use by a different process. This error is harmless; it happens after the submission has completed.

If the publication through the process is unsuccessful, it's likely because of [Specbreus](https://github.com/w3c/specberus), a spec compliance checker. Echidna automatically runs through Specbreus and will reject the publication if any error is reported by Specbreus. You can run your document through [Pubrules](https://www.w3.org/pubrules/) to understand why your document is rejected. You may modify either the index.bs file or the index.html file to ensure compliance. 

More often than not, you will discover the [Pubrules](https://www.w3.org/pubrules/) errors are due to bugs in either Bikeshed or Specbreus. If so, you will have to modify the compiled index.html file to bypass Echidna and use the [manual process](https://github.com/w3c/echidna/wiki/How-to-use-Echidna) to publish. While you are editing the html file to avoid errors, you should also check to ensure the document still renders correctly.  

The [manual process](https://github.com/w3c/echidna/wiki/How-to-use-Echidna) requires you to first create a tar file. To create the tar file, you need to first copy the index.html file and rename the copied file as Overview.html. This is because Echidna doesn't recognize index.html. You can then use the following command to create a tar file: 
```
tar -cvf WD.tar Overview.html image1 image2 image3
```

Then you can run the following command curl to publish to Echidna (use the command at the same directory as your tar file): 
```
curl 'https://labs.w3.org/echidna/api/request' --user '<username>:<password>' -F "tar=@WD.tar" -F "decision=<decisionUrl>"
```

Feel free to contact your chair or any W3C staff when you are stucked. Overall info on echidna is here: https://github.com/w3c/echidna/wiki and here https://labs.w3.org/echidna/.

# Taking meeting minutes

* [Scribe instructions from the W3C Guidebook](https://www.w3.org/2008/04/scribe.html)
* [Alternate instructions from the XML Security WG](https://www.w3.org/2008/xmlsec/Group/Scribe-Instructions.html)
