# Explainer: Hints for WebAuthn Clients

**Author:** Tim Cappalli <[tim.cappalli@okta.com](mailto:tim.cappalli@okta.com)>

**Last update:** April 15, 2025

## Summary

A new optional parameter to give WebAuthn clients hints about the desired starting point for the user interaction in the context of authenticator types/flows.

Also see: https://passkeys.dev/docs/advanced/client-hints/

## Background

`authenticatorSelection.attachment` has traditionally been used by Relying Parties to tell WebAuthn clients which type of experience they want to trigger: one that uses the local authenticator built-in to the device (`platform`) or one that uses an external authenticator such as a security key (`cross-platform`). This is an "authoritative" option and the client is expected to restrict the available options based on this value (e.g. only show security key option when `cross-platform` is used).

Passkeys changed some of that meaning as a passkey in a local authenticator could also be available to another device using cross-device authentication (CTAP 2.2 hybrid transports). This means that sending `authenticatorAttachment` = `cross-platform` now results in an experience driving the user to use their phone or a security key. In some environments, this can be very confusing.

Client Hints gives the RP the ability to send an ordered list of preferences, which the WebAuthn client can use to craft the appropriate UX, such as showing a security key dialog first, but allowing the user to select another flow from an overflow menu.


### Example use case

A workforce relying party only allows device-bound passkeys stored on security keys. It can confuse users if during a registration ceremony they first see the option to save a passkey to their phone.

By using the `security-key` hint, WebAuthn clients can optionally jump directly to the security key prompt instead of the user fumbling through other options to find it (and typically leading to failures).

For an authentication ceremony, the client can optionally ask the user to connect their security key instead of trying other options such as a phone with cross-device authentication.


## Changes

### New Enum Defined

```idl
enum PublicKeyCredentialHint {
    "security-key",
    "client-device",
    "hybrid",
};
```

### Optional "hints" member added to PublicKeyCredentialCreationOptions dictionary

Used with `navigator.credentials.create`.

This is processed by the client as an ordered list with the highest preference first.

```javascript
{
  "rp": {..},
  "user": {...},
  "challenge": "",
  "pubKeyCredParams": [...],
  "timeout": 60000,
  "excludeCredentials": [],
  "authenticatorSelection": {...},
  "attestation": "none",
  "hints": [
    "security-key"
  ],
  "extensions": {...}
}
```

### Optional "hints" member added to PublicKeyCredentialRequestOptions dictionary

Used with `navigator.credentials.get`.

This is processed by the client as an ordered list with the highest preference first.

```javascript
{
  "challenge": "",
  "timeout": 60000,
  "rpId": "",
  "allowCredentials": [...],
  "userVerification": "",
  "hints": [
    "security-key"
  ]
}
```

## Privacy considerations

This capability has no privacy impact.
