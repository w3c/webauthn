# Explainer: Embedded Credential Requests

## Authors

Andrew Comminos <<acomminos@meta.com>>, Paul Wright <<paulwright@meta.com>>

Last updated: 2026-10-26

## Summary

We propose a way for apps that embed web content (for example in-app WebViews) to make WebAuthn requests on behalf of relying parties (RPs) they are not associated with, without treating every such app as a trusted browser.

RPs opt in with a policy at `https://{rpId}/.well-known/webauthn` that allows or denies host apps by default, with per-app exceptions. When a request is permitted, the platform includes a platform-verified host app identifier, `hostAppId`, in `CollectedClientData`, where the authenticator's signature covers it. Platforms show a consent prompt that names the host app and require user verification for every embedded request.

## Goals

* Make passkeys usable inside embedded web content, which accounts for a large share of web traffic.
* Let RPs control which host apps may make requests on their behalf: allow-by-default with a denylist, or deny-by-default with an allowlist.
* Give RPs a verified signal identifying the host app, so they can apply their own risk decisions when they validate a response.
* Make sure users know which app is requesting a credential, and confirm the request explicitly.
* Add no user-facing friction for RPs that do not opt in or for host apps they have not permitted, and change nothing for apps already recognized as browsers.

## Non-goals

* System-provided browser views (Custom Tabs, `SFSafariViewController`, `ASWebAuthenticationSession`). These run in the context of the user's default browser and are already served by existing platform mechanisms.
* Requests from native apps associated with the RP (for example via Digital Asset Links or `apple-app-site-association`). These are already handled by existing platform mechanisms.
* Requests from apps the platform already recognizes as standalone browsers.

## Background

Apps that render web content can inspect and modify that content, including the RP's sign-in page. If any such app could use the platform credential manager for any origin, phishing would get easier: an app that renders the right origin is not, by that fact alone, trustworthy.

Platforms today therefore either restrict WebAuthn in embedded contexts or allow it only for apps recognized as browsers. As a result, users who follow an RP link inside an app often can't use their passkey, and the RP falls back to passwords or sends the user out to a browser. That gap holds back passkey adoption and leaves the ecosystem less secure overall.

Some platforms also let apps ship their own browser engines, so whether a request came from embedded web content can't be reliably determined by technical means alone. Any solution has to rest on the identity of the calling app, not on which WebView class it used.

## Proposal

We define an **embedded credential request** as a WebAuthn operation where both of the following hold:

* The request is on behalf of an RP that is not associated with the requesting app.
* The requesting app is not recognized as a standalone browser by the platform.

This covers in-app WebViews (for example Android `WebView` and `WKWebView`) and browser engines shipped inside apps.

The proposal has two parts:

1. **RP opt-in.** RPs opt in via the well-known endpoint, either allowing or denying host apps by default, with per-app exceptions. The platform client enforces this policy before showing any UI.
2. **Platform-verified host app identity.** When the policy permits the request, the platform includes `hostAppId` in `CollectedClientData`, set from the calling app's verified identity before the request reaches the authenticator. In embedded requests `origin` is supplied by the host app; `hostAppId` is the field the platform vouches for.

RPs therefore get visibility into, and control over, the apps that make embedded requests, without having to trust a potentially malicious client.

### Opting in to embedded requests

RPs opt in by extending the existing `.well-known/webauthn` resource defined for [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins):

```
https://{rpId}/.well-known/webauthn
```

The platform client fetches this policy directly from the RP's origin, so a malicious host app can't forge an opt-in.

#### Policy format

```json
{
  "embedded": {
    "default": "deny",
    "exceptions": [
      "android:com.example.partner:xA2K8aYJFh0kLQPD6...",
      "android:com.example.partner:Qm9zc2FuY2VydA...",
      "ios:T84QZS65DQ.com.example.partner"
    ]
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `embedded.default` | `DOMString` | Yes | `"deny"`: only host apps listed in `exceptions` are permitted. `"allow"`: every host app is permitted except those listed in `exceptions`. |
| `embedded.exceptions` | `sequence<DOMString>` | No | Host apps whose `hostAppId` exactly matches an entry get the opposite of `default`. If absent, treated as an empty list. |

This supports three RP configurations:

* **Allowlist:** `"default": "deny"` with `exceptions`. Only the listed host apps may make embedded requests.
* **Denylist:** `"default": "allow"` with `exceptions`. Every host app except the listed ones may make embedded requests.
* **Not opted in (today's behavior):** if `embedded` is absent or invalid, no embedded requests are permitted. `"default": "deny"` with no exceptions has the same effect.

Entries in `exceptions` use the same format as `hostAppId` (see [Example `hostAppId` formats](#example-hostappid-formats)). As with `sha256_cert_fingerprints` in Digital Asset Links, an app signed with multiple certificates (for example after a key rotation) is listed once per certificate.

`default` is required, and the denylist is expressed as exceptions to it rather than as a separate list alongside a boolean. That way, a client that doesn't understand a policy can't mistake a restricted policy for unrestricted permission.

#### When a host app is not permitted

Whether a request is permitted depends on its RP ID, which is only known when `create()` or `get()` is called, and on a policy that is fetched asynchronously. Platforms that support embedded requests therefore expose the WebAuthn API to embedded content and enforce the policy per request.

When the policy does not permit the requesting host app, the platform client fails the operation without displaying any user-facing UI and without invoking an authenticator. That includes the cases where no policy exists, the policy can't be fetched, or it is invalid. Where a platform can determine ahead of time that no embedded request will be permitted (for example, because the host app has not enabled embedded requests), it MAY instead leave `create()` and `get()` unexposed, as embedded contexts behave today.

Because the policy checks complete before any user-facing UI, an RP that doesn't support a given host app adds no friction for the user: the operation fails, and the page falls back the way it already does, for example by offering another sign-in method or by sending the user to their default browser. Which error the operation rejects with is an [open question](#open-questions).

The policy applies to both `create()` and `get()`. When it permits the requesting app, both operations are supported and `hostAppId` is included in `clientDataJSON` for each.

### `CollectedClientData` extension

```webidl
partial dictionary CollectedClientData {
  DOMString hostAppId;
};
```

| Field | Type | Required | Description |
|---|---|---|---|
| `hostAppId` | `DOMString` | No | The platform-verified identifier of the app making the embedded request. |

For requests that are not embedded requests (for example from recognized browsers), `hostAppId` is omitted.

#### Example `clientDataJSON`

```json
{
  "type": "webauthn.get",
  "challenge": "dGVzdC1jaGFsbGVuZ2U",
  "origin": "https://example.com",
  "crossOrigin": false,
  "hostAppId": "android:com.example.myapp:xA2K8aYJFh0kLQPD6..."
}
```

`hostAppId` doesn't change `crossOrigin`, which keeps its existing semantics: `false` for top-level embedded content (as in this example), and `true` for requests from cross-origin iframes within it. Existing `topOrigin` and Permissions Policy behavior also stays as it is.

### Platform client processing

The platform client (for example Android Credential Manager or iOS AuthenticationServices) handles a WebAuthn request as follows:

1. Determine whether the request is an embedded credential request.
2. If it is not, proceed with the standard WebAuthn flow, and omit `hostAppId`.
3. If it is, complete steps 4–7 before displaying any user-facing UI. If the host app is not permitted at any step, follow [When a host app is not permitted](#when-a-host-app-is-not-permitted).
4. Fetch the RP's policy from `https://{rpId}/.well-known/webauthn` over HTTPS, using the platform client's own networking stack.
5. If the fetch fails, the policy has no `embedded` member, or `embedded.default` is neither `"allow"` nor `"deny"`, the host app is not permitted.
6. Determine `hostAppId` from the calling app's verified identity (for example, its signing certificate). The platform client constructs or validates `clientDataJSON` and sets `hostAppId` to this value; host apps (including the platform WebView) supply the remaining client data. If a host app supplies a `hostAppId` that doesn't match its verified identity, reject with `SecurityError`.
7. If `embedded.default` is `"deny"` and `embedded.exceptions` doesn't contain `hostAppId`, or `embedded.default` is `"allow"` and `embedded.exceptions` contains it, the host app is not permitted.
8. Display a consent UI that tells the user which app is making the request and lets them make an informed choice about whether to continue. If the user declines, reject with `NotAllowedError`.
9. Treat `userVerification` as `required`, so that the authenticator performs user verification and sets the UV flag in the response.
10. Continue with the standard WebAuthn flow, with `hostAppId` included in `clientDataJSON`.

### Host app requirements

Apps embedding web content through the platform WebView need no changes beyond enabling embedded WebAuthn support in that WebView (for example, through a WebView setting). The platform derives `hostAppId` from the app's existing signing identity, so there are no association files to host, keys to manage, or allowlists to maintain on the app side.

Apps shipping their own browser engine pass the client data to the platform client, rather than only its hash, and the platform client sets `hostAppId` in the same way.

### Relying party validation

After receiving a response, the RP:

1. Performs standard WebAuthn verification, which covers the hash of `clientDataJSON`.
2. Parses `clientDataJSON` and reads `hostAppId`:
    * If it is absent, the request was not an embedded request, or the client doesn't implement this proposal. No new validation is needed. Absence is not proof that the request came from a trusted browser.
    * If it is present, the request was made by a host app. The RP applies whatever allowlist or denylist logic it needs. RPs that specify `exceptions` should enforce the same policy here, because platform clients may cache the policy file.

RPs MAY apply stricter risk policies to embedded requests. For example, an RP might accept embedded `get()` requests while declining to register new or replacement credentials through embedded `create()`.

### Example `hostAppId` formats

These platform-specific identifiers are non-normative possibilities, loosely inspired by [FIDO AppID and Facets](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html), Digital Asset Links, and `apple-app-site-association`:

| Platform | Format | Example |
|---|---|---|
| Android | `android:<package>:<base64 SHA-256 of APK signing cert>` | `android:com.example.myapp:xA2K...` |
| iOS | `ios:<team_id>.<bundle_id>` | `ios:T84QZS65DQ.com.example.myapp` |

Any assignment needs to:

1. Be namespaced to the platform, to prevent collisions (for example `android:`, `ios:`).
2. Identify the host app's publisher unambiguously, including where package IDs alone are not unique across publishers (for example Android package names).

## Security considerations

### Phishing

Letting more apps make requests on behalf of other RPs' origins inherently increases phishing risk. This proposal mitigates it by letting RPs restrict embedded requests to partners they trust, or block apps they know to be malicious.

An RP that uses a permissive denylist can still let a malicious app through. That risk is under the RP's control, and the RP decides how much of it to accept.

Platforms MUST also show consent UI identifying the host app, and MUST require user verification, for every embedded request. A host app therefore can't trigger a ceremony silently or without the user's knowledge. Consent and user verification don't eliminate social engineering, and a permitted host app can still observe the page and session.

### Integrity of `hostAppId`

The platform client sets or validates `hostAppId` against the calling app's verified identity, and computes the client data hash itself, before forwarding the request to an authenticator. Because `hostAppId` is part of `clientDataJSON`, the authenticator's signature covers it, so a malicious host app can't forge it.

`origin`, by contrast, is supplied by the host app in an embedded request, and the host app controls the page. RPs should rely on `hostAppId`, not `origin`, to identify the embedder.

`hostAppId` is a claim made by the platform. Like `origin`, it may not hold if the device is rooted or compromised.

### Registration assurance

For `create()`, `hostAppId` is returned in `clientDataJSON`, but a response with `none` attestation carries no attestation signature over it. The assurance RPs can rely on for embedded registrations needs further discussion. See [Open questions](#open-questions).

### Policy staleness

Platform clients may cache the policy. Changes to `exceptions` can therefore take a while to take effect, for example removing an app under `"deny"` or adding one under `"allow"`.

Platforms can limit this by honoring HTTP caching headers, subject to a bounded maximum TTL. RPs that need immediate revocation can enforce `hostAppId` when they validate responses.

## Privacy considerations

### Cross-RP tracking

Any use of WebAuthn in a WebView-based browser may let the app learn whether the user has credentials for a given RP. This is a fundamental consequence of enabling sign-in: apps can already infer it today by watching for successful password logins.

Platforms mitigate this by requiring informed user consent that identifies the host app before any credential is used for an embedded request.

### Fingerprinting

New identifiers describing the user agent can be used for fingerprinting. Platforms should expose only the minimum information needed to establish trust in the host app, such as package IDs without versions.

This reflects how embedded content works today. Many in-app browsers already append app identifiers to their User-Agent string, and Android WebView has historically sent the host app's package name in the `X-Requested-With` header. `hostAppId` replaces those spoofable, always-on signals with a platform-verified one that is disclosed only to RPs that have opted in.

There is precedent for exposing app identity to RPs: Android Credential Manager already sets `origin` to `android:apk-key-hash:<hash>` in `clientDataJSON` for requests from native apps. `hostAppId` is narrower in scope:

* It is present only when the RP has opted in.
* It is never sent for apps already recognized as browsers.
* It identifies only the app, not its version or the user's device.

RPs using `"default": "deny"` learn nothing beyond the set of apps they already listed. RPs using `"default": "allow"` may receive identifiers for apps they didn't enumerate.

## Interoperability considerations

Once RPs can see which app is making an embedded request, some may restrict embedded requests aggressively. That could limit legitimate use from third-party apps the RP doesn't otherwise know about.

We believe this tradeoff is necessary, because platforms have no scalable way to identify "good" WebView embedders with appropriate phishing protections. Platforms should not include or require `hostAppId` for apps already recognized as browsers.

## Alternatives considered

### Per-app opt-in only

RPs could list permitted apps only in the well-known policy, without `hostAppId` appearing in responses. That would avoid exposing platform-specific identifiers through WebAuthn. But RPs couldn't apply their own logic at response time, such as risk-based decisions, immediate revocation regardless of policy caching, or stricter handling of embedded `create()`.

We instead offer both: a policy the platform enforces, and `hostAppId` in `clientDataJSON` for RPs that want to apply additional logic.

### Digital Asset Links / `apple-app-site-association`

The allowlist could be expressed through existing platform association files instead of `.well-known/webauthn`.

Reusing the existing relations (`delegate_permission/common.get_login_creds`, `webcredentials`) would convey the wrong level of trust. Those relations declare the app *associated* with the RP, which makes its requests non-embedded by definition and gives it native access to the RP's credentials. RPs that want an allowlist are asking for a middle tier: a partner may host the RP's web login inside a WebView, with the RP's origin still asserted.

Defining new relations in both formats would work, but it splits one policy across three files, and it needs each platform vendor to extend its own format independently. The global opt-in has to stay in `.well-known/webauthn` to remain platform-agnostic. And since `hostAppId` already needs a canonical identifier format for RP validation, keeping the allowlist in `.well-known/webauthn` costs little extra.

### Origin-based host app identification

We considered exposing a `hostAppOrigin` instead of an app identifier. However:

* One host app can be associated with multiple origins, since Digital Asset Links relations allow it.
* An origin doesn't uniquely identify an app, and could permit embedded requests in more cases than intended.

### Authenticator extension

This could be built as a new authenticator extension instead of a `CollectedClientData` member. We chose `CollectedClientData` because:

1. It makes clear that verifying the host app is the client platform's job, independent of the authenticator, as validating `origin` is today.
2. Existing authenticators don't need to change, so platforms can provide and scale this functionality themselves.
3. It is simpler, and pairs naturally with the existing `origin` field.

## Open questions

* **API behavior:** which error a non-permitted request rejects with: `NotAllowedError`, which is indistinguishable from user cancellation apart from timing, or a distinct error that lets RPs offer a better fallback (the RP already knows its own policy, so this reveals little). Also what feature detection (`PublicKeyCredential`, `getClientCapabilities()`, `isConditionalMediationAvailable()`) reports when support depends on the RP ID, and abort handling and navigation races while the policy is being fetched.
* **Registration assurance:** what assurance `hostAppId` gives on `create()`, particularly with `none` attestation, and whether embedded registration needs additional constraints.
* **Identifiers:** canonical encoding (base64 vs. base64url), publisher uniqueness, multiple signers and key rotation, app transfers, and how other platforms are namespaced.
* **User experience:** how the app is displayed in consent UI, repeat consent, interaction with conditional and immediate mediation, authenticators without user verification, and existing iframe permission rules.

## References

* [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/): §5.8.1 Client Data, §5.11.1 Related Origins, §7 RP operations, §8.7 None attestation
* [FIDO AppID and Facets](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html)
