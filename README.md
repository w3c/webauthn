
# Web Authentication Specification

This is the repository for the W3C WebAuthn Working Group, producing the draft **"Web Authentication"** specification.

* [The editor's copy is available at https://w3c.github.io/webauthn/](https://w3c.github.io/webauthn/), or in the [`gh-pages` branch of this repository](https://github.com/w3c/webauthn/blob/gh-pages/index.html).
  - The current *offically published working-draft snapshot* [is here: https://www.w3.org/TR/webauthn/](https://www.w3.org/TR/webauthn/).
* [The build history is available from the repo Actions tab](https://github.com/w3c/webauthn/actions)
* [W3C WebAuthn Blog](https://www.w3.org/blog/webauthn/)
* [Web platform tests repository](https://github.com/web-platform-tests/wpt/tree/master/webauthn)

# Contributing

To materially contribute to this specification, you must meet the requirements outlined in [CONTRIBUTING.md](/CONTRIBUTING.md). Also, before submitting feedback, please familiarize yourself with [our current issues list](https://github.com/w3c/webauthn/issues) and review the [mailing list discussion](https://lists.w3.org/Archives/Public/public-webauthn/).

# Building the Draft

(see the next section if you use `mise`)

The following are required before continuing:

- Python 3.13
- [uv](https://docs.astral.sh/uv/getting-started/installation/)

Run the following commands to set up your local development environment to work on these specifications:

```
uv sync
```

```
uv run -m bikeshed update
```

Formatted HTML for the draft can then be built with the following command:

```
uv run -m bikeshed spec
```

You can use the `watch` functionality to automatically regenerate the rendered document as you make changes locally:

```
uv run -m bikeshed watch
```

Running the following command from the root of this repo will let you view the rendered document at http://127.0.0.1:8000:

```
uv run -m http.server -b 127.0.0.1
```

## Using mise

If you use [mise](https://mise.jdx.dev/), run the following commands to set up your local development environment to work on these specifications:

`mise run setup`

`mise run update`

Formatted HTML for the draft can then be built with the following command:

`mise run build`

You can use the `watch` functionality to automatically regenerate the rendered document as you make changes locally:

`mise run watch`

Running the following command from the root of this repo will let you view the rendered document at http://127.0.0.1:8000:

`mise run serve`

# Continuous Integration & Branches

https://w3c.github.io/webauthn/ is autopublished from the `gh-pages` branch on every push to the `main` branch, using https://github.com/w3c/webauthn/blob/main/.github/workflows/build-validate-publish.yml to configure the autopublishing behavior.
