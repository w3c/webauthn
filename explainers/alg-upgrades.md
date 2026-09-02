# **Explainer: Algorithm Upgrades**

## Authors

Nina Satragno <nsatragno@google.com>

## Summary

Allow seamlessly upgrading users from credentials backed by classical algorithms to PQC algorithms.

_This proposal is intended as a simpler alternative to Akshay's [WebAuthn Algorithm Policy (PQC Migration & Cryptographic Agility)](https://github.com/w3c/webauthn/blob/main/explainers/alg-policy.md). It is conceptually a subset of that proposal, with significant changes to simplify it and more details on extension handling._

## Goals

* It should be possible to upgrade users to a new algorithm during a `get()` request.  
* Users should not be locked out if the results of a `get()` request don't make it to the relying party's server.  
* WebAuthn extensions should continue to work after the migration.  
* The upgrade should happen as transparently as possible for users.  
* The upgrade should be algorithm agnostic.  
* The change should work well for platform, roaming, syncing and device-bound authenticators.

We want the simplest solution that meets our goals, since new complexity will cut across every layer of the ecosystem: relying parties, user agents, OS level APIs, passkey providers, and security keys.

## Non-goals

* Rotating credentials within the same algorithm.  
* Providing a composite signature scheme on top of the WebAuthn protocol.  
* Allowing the relying party to select between a set of previously agreed upon keys at sign in time.

## High level proposal

The problem can be reduced to two independent capabilities:

* A relying party should be able to request a credential creation alongside an assertion.
* A relying party should be able to identify that a previous migration was not successful and issue a request to recover the credential.

We propose two independent additions to WebAuthn, one for each capability.

## Backing up and restoring overridden credentials

Currently, WebAuthn stipulates that authenticators [store credentials in a map](https://w3c.github.io/webauthn/#authenticator-credentials-map) where the key is a tuple `{ user id, RP ID }`. This means that a user can only have one credential of one type on a given authenticator. Overwriting a credential is a dangerous operation: if a problem occurs when storing the credential on the relying party server, then the old credential is no longer available.

We propose having the `{ user id, RP ID }` tuple map to a list of credentials, sorted by creation time. Whenever a new credential is created, it will be appended to the tuple. Empty allow-list assertion requests will always return the newest credential in the tuple.

Whenever an allow-list request is received by an authenticator, the authenticator will find the most recent credential ID it has that matches the allow-list. Every other credential for that `{ user id, RP ID }` tuple will be erased. Additionally, authenticators will reserve the right to clean up old credentials if it becomes necessary to make space for new credentials.

This capability will be accompanied by an assertion authenticator extension reporting the list of currently backed up credential IDs.

```
partial dictionary AuthenticationExtensionsClientInputs {
  boolean restoreCredentials;
};

dictionary RestoreCredentialsOutput {
  sequence<ArrayBuffer> existingCredentials;
}

partial dictionary AuthenticationExtensionsClientOutputs {
  RestoreCredentialsOutput restoreCredentials;
};

$$extensionInput //= (
  restoreCredentials: true
)

// Signed extension outputs.
$$extensionOutput //= (
  restoreCredentials: {
    existingCredentials: [* bstr],
  }
)
```

If an assertion fails to match a credential record on the relying party database, the relying party can find the intersection between `existingCredentials` and its list of credentials for the user, and issue a new allow-list request. `existingCredentials` will help the relying party distinguish between a passkey the user deleted on the server vs a passkey upgrade request that did not make it to the server.

The behaviour to restore credentials with an allow-list request will always be present for authenticators supporting it independent of the relying party requesting the extension.

### CTAP authenticators

An interesting feature of stateless credentials is that they already behave as if having this capability today for every credential ever created. However, it's impossible for the authenticator to know the list of stateless credentials it has issued. Thus, `existingCredentials` will return `[]` for stateless credentials. This shouldn't matter much since the only way to get an assertion for a stateless credential is by providing an allow-list anyway.

## Algorithm upgrade extension

Having multiple credentials per user is enough to have some form of upgrade path involving first getting an assertion, then issuing a new request to create a credential. However, it's not enough: the user could tap a different authenticator for the new credential. There's no blessing of the new credential by the existing one. And, it's bad UX to have every user sometimes have to go through the WebAuthn ceremony twice.

Our proposal is that the relying party needs to be able to create a new credential as part of an assertion request. The user authorizes an authentication like normal, and the response may contain a new credential alongside the assertion. We will standardize a new `algUpgrade` WebAuthn extension to do this:

```
dictionary AuthenticationExtensionsAlgUpgradeInputs {
  // Parameters for the new credential.
  required sequence<PublicKeyCredentialParameters> pubKeyCredParams;
}

dictionary AuthenticationExtensionsAlgUpgradeOutputs {
  // Make credential authenticator data.
  ArrayBuffer authenticatorData;
};

// Signed extension outputs.
$$extensionOutput //= (
  algUpgrade: {
    // Make credential authenticator data.
    authData: bstr,
  }
)
```

Upon receiving this extension, a capable authenticator will examine the list of algorithms on `pubKeyCredParams`, finding the first algorithm `alg` it supports. If a credential for the RPID and user id with `alg` exists, the authenticator will complete the get assertion operation like usual.

Otherwise, the authenticator will create a new credential with `alg` and generate a corresponding `authenticatorData` structure. The authenticator will then use the old credential to generate a normal assertion, including the new `authenticatorData` as part of the signed extension outputs. This operation transfers trust from the original to the newly created credential[^2].

Only authenticators supporting restoring credentials will be eligible to expose this extension.

### Attestation

Newly created credentials using this extension don't have a way to carry an [attestation](https://w3c.github.io/webauthn/#attestation-statement). If the relying party trusted the attestation at the time the credential was created, it should trust the new credential because it is signed by the existing one.

### Extensions

Newly created credentials using this extension are banned from outputting extensions as part of their `authenticatorData`. Only assertion time extensions will be handled when creating a credential in this way, and the outputs will be included in the extension outputs of the original credential. In other words, this API will not allow relying parties to create credentials with extensions that the original credential didn't have.

When it makes sense, extension secrets are transferred from the original credential to the new one.

#### *Credential Manager Trust Group (CMTG) keys*

[CMTG keys](http://go/chrome-cmtg) are specified to be the same algorithm as the private key.

The current specification indicates that a single CMTG key may be returned by an assertion request. We should [change](https://github.com/w3c/webauthn/issues/2472) this to instead return a list of keys. On an assertion, the authenticator will check the list of eligible CMTG keys. If the list does not contain any keys using the selected algorithm, a new CMTG key is minted and returned alongside the existing key. This lets us transfer trust from the previous key to the new one.

Unlike with passkeys themselves, a newly minted CMTG key being lost in transit is not that big of a deal, the user won't be locked out of their account since RPs have to contend with that for users on new trust groups. So once the authenticator has returned a CMTG key for a new algorithm, it may remove the matching credential for the old algorithm.

#### *Large blob*

The large blob will be transferred from the existing credential to the new one. This may take the form of having both credentials point to the same large blob object, or copying it from one credential to the next. Copying happens after processing a large blob write, if present.

For example, for CTAP, the easiest way to implement this change is to copy the `largeBlobKey` from the old credential to the new one.

Data consistency between the main credential and any credentials kept as backups is not guaranteed. However, this should not be a problem if the relying party uses the `restoreCredentials` extension as intended, since only one credential would be the active one at any given time.

#### *Credblob*

Credblob enables RPs to provide a small amount of extra credential configuration information to the authenticator when a credential is made and does not allow updating it. It should be copied to new credentials.

#### *PRF & hmac-secret*

Returned PRF values should be the same for the new credential. This can be done by copying the  `hmac-secret` values to the new credential.

#### *Third party payment*

The third party payment bit is copied to new credentials.

#### *credProtect*

New credentials will copy the `credProtect` value from the previous credential.

#### *Other extensions*

`credProps` doesn't need to be wired since the credential will have the same properties.

`appId` and `appIdExclude` don't need to be considered since U2F devices won't be upgrade eligible authenticators.

`remoteClientDataJson` does not need any special handling.

`minPinLength` and `pinComplexityPolicy` don't need to be handled because they'll match the original credential.

### CTAP authenticators

Security keys don't have screens for the user to select a credential[^3]. For empty allow-list requests, they return a list of assertions to the client platform, which displays them to the user to select. It would not be desirable to have the security key upgrade credentials the user hasn't selected. Allow list requests, on the other hand, only ever return a single credential, so they don't have this problem.

We should specify a mirror of this extension on CTAP that only works for requests that resolve to a single credential. If a request resolves to more than one credential, the extension will not be processed.

In order to support this for empty allow-list requests, client platforms will use the [credential management commands to enumerate credentials for the RP ID](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#enumeratingCredentials). First, the platform will request a tap for a new pin token. Then, it will enumerate the credentials to show the UI. Finally, the platform will issue a get assertion command with an allow list containing the selected credential. In some cases, like NFC security keys, this may result in needing another tap. For USB security keys, this should not result in an extra tap, as the user presence is consumed only after the get assertion request.

## Relying party actions

Relying parties will pass the list of accepted algorithms, sorted by preference, on `get` requests. If they get a new credential in the `algUpgrade` extension, they'll replace the existing credential with the new one.

```javascript
// client.js
// accounts/signin
const assertion = await navigator.credentials.get({publicKey: {
  ...
  extensions: {
    algUpgrade: {
      pubKeyCredParams: [
        { alg: -48, type: 'public-key' },  // ML-DSA-44.
        { alg: -7, type: 'public-key' },   // ECDSA.
      ],
    }
  }
}});

fetch('webauthn/assert', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(assertion.toJSON())
});

// server.js
// webauthn/assert

// [Validate the assertion.]

let cborExtensions = parseExtensions(assertion.response.authenticatorData);
let newCredential = cborExtensions.algUpgrade?.authenticatorData;
if (newCredential) {
  // [Replace the user's credential.]
}

// [Continue with sign in as normal.]

```

For a relying party to switch to a new algorithm, it should be enough to update the `pubKeyCredParams` list as needed.

### Recovering from an upgrade that doesn't make it to the server

Suppose a relying party `bank.com` uses security keys as a second factor and would like to upgrade from algorithm A to algorithm B. The new credential B doesn't make it to the server, because the user lost their internet connection. Next time the user signs in, `bank.com` sends an allow-list that contains A but no B. The authenticator can return an assertion for A[^4] and clean up B. Notably, `bank.com` didn't have to do anything to be protected against this side effect.

Usernameless flows are not quite so fortunate. Suppose shrine.com uses passkeys as a primary factor and is in the same situation. shrine.com sends an empty allow-list request and the passkey provider returns passkey B, which shrine.com does not recognize. shrine.com can perform the following operations:

* Check if the existingCredentials list is empty. If empty, there is no backed up credential. Offer the user some other way to sign in.
* Find the intersection between existingCredentials and the user's credentials, using the returned user id from the assertion.
* If the intersection is empty this most likely means that the user manually deleted the passkey from the relying party's account management UI. Call signalUnknownCredential for that passkey and let the user know they have to try to sign in some other way.
* Else, the user tried to upgrade a credential but the upgrade never made it to the server. Issue a new allow-list request.

This approach unfortunately would require two ceremonies, but design alternatives that don't have this problem come with other less desirable trade-offs.

### Dogfooding

One disadvantage of this design is that the relying party cannot target which user gets an upgrade request on empty allow-list flows. This makes dogfooding more challenging, but still possible. A relying party could e.g. drop a cookie that remembers whether a device is eligible for upgrade or not.

### Trusting the old credential

Our hope is that the majority of relying parties will start upgrading credentials while they still trust the current algorithms. Ease of recovery is predicated on this fact. Suppose that after quantum computers become commonplace, a relying party sees an assertion for a user with an unknown credential ID. The relying party should not accept this credential as proof of authentication, as it may be an attacker trying to force the relying party to accept a classical algorithm. In that case, the safest option would be to not trust a classical credential, treat it as an authenticator that was never upgraded, and step the user up with some other means of authentication.

The design of this API does not absolve relying parties from having to judge which set of algorithms they trust.

### Reliance on user IDs

The WebAuthn spec mandates that [user handles](https://w3c.github.io/webauthn/#user-handle) are unique per user, and states:

> It is RECOMMENDED to let the user handle be 64 random bytes, and store this value in the user account.

The signal API relies on each user being assigned a single user handle, and to some extent so does this proposal. However, it should still be possible to restore credentials even if a given user holds multiple user handles, by issuing a request with *all* credential IDs corresponding to a user identified by that user id.

If a relying party were to repeat user handles between their users, their implementation would be fundamentally broken as they wouldn't support having more than one user credential on the same authenticator. Supporting such relying parties is a non-goal.

[^2]:  As an alternative, we could include a hash of the `authenticatorData` or a hash of the credential ID \+ COSE key. However, it's not clear if this extra complexity is warranted.

[^3]:  CTAP supports this feature, but I've yet to see one of these keys.

[^4]:  An interesting feature of stateless credentials is that they already behave as if having this capability today. Unfortunately, it's not currently possible to tell if a given security key credential is stateless or resident. Non-discoverable credentials are not guaranteed to be stateless.