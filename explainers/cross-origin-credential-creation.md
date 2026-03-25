# Explainer: Cross-Origin Credential Creation

**Author:** Matthew Miller \<[mattmil3@cisco.com](mailto:mattmil3@cisco.com)\>

**Last update:** April 23, 2025

## Summary

Support for making calls to `navigator.credentials.create()` from a website embedded in an iframe on a different origin.

## Background

Relying Party websites embedded in an iframe on another website were empowered in WebAuthn L2 to request WebAuthn assertions to facilitate sign-in. That is, a website “bank.com”, embedded in the site “example.com”, could make a call to `navigator.credentials.get()` with `rp.id` set to “bank.com” despite the top-level origin being “example.com”. Cross-origin credential **registration** was deferred to later, though, for lack of a strong, tangible use case.

Payments-related regulations in Europe, like PSD2 that requires banks to authenticate their users inside the context of a 3rd-party service-provider's site, identified a concrete benefit to allowing embedded websites, already using cross-origin credential assertion, to request registration of a WebAuthn credential as well. In response to this the decision was made to unblock cross-origin calls to `navigator.credentials.create()` for such Relying Parties in L3.

### Example use case

A bank embedded on a merchant’s site can request registration of a passkey that can be used in subsequent purchases to streamline the checkout process.

Third-party authentication services embedded on a website to handle authentication on the embedding site’s behalf can now also handle new user account registration.

## Changes

A new `publickey-credentials-create` token was established as an acceptable value for an iframe’s `allow` attribute. When set and a user gesture is provided, the website within the iframe will be allowed to successfully invoke `navigator.credentials.create()`

```html
<iframe  
  src="https://webauthn.io"  
  frameborder="1"  
  style="width: 1000px; height: 600px;"  
  allow="publickey-credentials-create"  
></iframe>  
```

A new `topOrigin` value has been added to `clientDataJSON` to convey the fully-qualified top-level origin. This value is populated in responses only when WebAuthn calls are made from a cross-origin context.

## Privacy considerations

Embedded Relying Parties can learn the top-level origin from the `clientDataJSON.topOrigin` value. However if there is an assumption that the embedded Relying Party and top level website embedding the RP have established a relationship prior to embedding one in the other then this represents no change in impact to user privacy.
