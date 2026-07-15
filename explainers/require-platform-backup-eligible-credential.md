# Explainer: WebAuthn `requireBackupEligibleCredential`

**Author**: Nina Satragno <nso@google.com>

**Status**: Retired

## Status

This proposal was retired, see the discussion at <https://github.com/w3c/webauthn/issues/2342>.

## Summary

A new `AuthenticatorSelectionCriteria` parameter that lets a relying party indicate that only [platform authenticators](https://w3c.github.io/webauthn/#platform-authenticators) that support [backing up credentials](https://w3c.github.io/webauthn/#sctn-credential-backup) (i.e. syncing) should be eligible.

## Background and motivation

Synced WebAuthn credentials (passkeys) are designed as a replacement for passwords. For this to work, the requirement that the passkey is synced is key, otherwise a user who loses the device with their credential also loses access to their account.

The WebAuthn API has evolved organically from security keys to serve a complex ecosystem where an increasing number of users are served by providers with the ability to securely sync passkeys. However, there remain a few notable platform authenticators without the ability to sync. Currently, there is no way to specify that these providers should be excluded from the list of eligible authenticators. This presents a problem for relying parties who want to move away from passwords, as they cannot guarantee that their users will end up in a safe state after a sign-up flow.

Relying parties can only tell after the passkey was created whether it can sync or not by looking at the [backup eligibility](https://w3c.github.io/webauthn/#backup-eligibility) bit. This is undesirable if we want the passkey to be the main way to sign in.

## Design

The Chrome WebAuthn team proposes a new `AuthenticatorSelectionCriteria` `requireBackupEligibleCredential` attribute that lets a relying party indicate that only platform authenticators that support syncing should be eligible to serve a make credential request. This field will be similar to `authenticatorAttachment: "platform"` but will additionally filter out platform authenticators that don't support syncing. Setting this field will give relying parties a guarantee that they can rely on just having the passkey for authentication.

### Feature detection

The local availability of a backup eligible credential must be detectable by the relying party before the request to inform the UI they present to the user. We'll extend `ClientCapabilities` with a new parameter:

* `isPlatformBackupEligibleAuthenticatorAvailable`
  
  This will both indicate that the browser understands the option and that such an authenticator is available.

## Relying party actions

Relying parties should first feature detect the API. If the API is not supported, the relying party should either start with an email or password based authentication method, or look at the [backup eligibility](https://w3c.github.io/webauthn/#backup-eligibility) bit after a passkey is created to determine the best course of action.

```javascript
// sign_in_button_handler.js:

// Feature detection.
let capabilities = await PublicKeyCredential.getClientCapabilities();
if (!capabilities["isPlatformBackupEligibleAuthenticatorAvailable"]) {
  proceedWithRegularSignUp();
  return;
}

let credential = await navigator.credentials.create({
  publicKey: {
    // ...
    authenticatorSelection: {
      requireBackupEligibleCredential: true,
      residentKey: "required",
      userVerification: "preferred",
    },
    // ...
});
```

Relying parties can then safely create a new account with the result of the response.

`requireBackupEligibleCredential` is intended to replace `authenticatorAttachment: "platform"` for relying parties who don't want to deal with the complexity of supporting multiple authentication mechanisms to prevent account lock-out.

### [`authenticatorAttachment`](https://w3c.github.io/webauthn/#enum-attachment) value

[`authenticatorAttachment`](https://w3c.github.io/webauthn/#enum-attachment) would be ignored. Setting it to `cross-platform` with `requireBackupEligibleCredential` is nonsensical anyway. Relying parties would be recommended to set the value to `platform`. (A viable alternative is to make `requirePlatformBackupEligibleCredential` an `AuthenticatorAttachment` value instead.)

### [`residentKey`](https://w3c.github.io/webauthn/#enum-residentKeyRequirement) value

[`residentKey`](https://w3c.github.io/webauthn/#enum-residentKeyRequirement) will function the same it already does for the `platform` `authenticatorAttachment`, which in practice means that most authenticators will store a discoverable credential regardless of its value. Relying parties would be recommended to set the value to `required`.

## Ecosystem considerations

### Previously rejected proposals for authenticator selection

In the past, there have been similar proposals going the opposite way, e.g. [issue 1714](https://github.com/w3c/webauthn/issues/1714). These have been some form of restricting the list of eligible WebAuthn authenticators to be only [device-bound credential](https://w3c.github.io/webauthn/#single-device-credential) capable. These proposals were rejected on the basis that they would harm the ecosystem through fragmentation, limiting the usability of passkeys on the web.

The present proposal, while appearing similar on the surface, is different enough to warrant consideration. Authenticators are and have been moving towards syncing, not the other way around. With Microsoft [announcing synced passkeys are coming to Windows](https://blogs.windows.com/windowsdeveloper/2024/10/08/passkeys-on-windows-authenticate-seamlessly-with-passkey-providers/), the overwhelming majority of users will have access to a synced provider soon (the opposite is true of device-bound authenticators). Limiting authenticators to syncing only can help bring some coherence to relying parties that don't want and don't need to have their users deal with the UX challenges of pre-syncing authenticators.

## Privacy considerations

`isPlatformBackupEligibleAuthenticatorAvailable` would reveal to a relying party that a user has access to a syncing authenticator, which usually means they are signed in to their sync account provider. This doesn't immediately seem like it could be used to cause harm, and if this proposal serves to further the extinction of passwords from the web, then the adding a bit of fingerprinting entropy seems like an acceptable trade-off.

## Alternatives considered

### Add a [user-agent hint](https://w3c.github.io/webauthn/#enum-hints) instead

We decided not to propose a new user-agent hint, as this would be ineffective if the user either doesn't have access to a syncing authenticator on their platform / user agent, and relying parties would still need to handle the case where the user selects an authenticator that does not support syncing.

### Don't do anything and rely on the [backup eligibility](https://w3c.github.io/webauthn/#backup-eligibility) bit

Relying parties could let a user create a credential and then determine its suitability after the fact. This approach was discarded early because it leads to an unfortunate UX for users who select an authenticator that doesn't sync.
