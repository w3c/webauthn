## Simplified Web Authentication PQC migration extension

### Authors

Nina Satragno <nsatragno@google.com>

### Summary

This proposal is intended as a simpler alternative to Akshay's [WebAuthn Algorithm Policy (PQC Migration & Cryptographic Agility)](https://github.com/w3c/webauthn/blob/main/explainers/alg-policy.md). It is conceptually a subset of that proposal, with some additional changes to reuse existing infrastructure.

The intention is to allow seamlessly upgrading users from credentials backed by classical algorithms to PQC algorithms.

### Goals

If you've read the original Algorithm Policy proposal, these are the same:

* It should be possible to upgrade users during a `get()` request.
* Users should not be locked out if the results of a `get()` request don't make it to the relying party's server.
* The feature should be algorithm agnostic.
* The change should be backwards compatible. 
* The change should work well for platform, roaming, syncing and device-bound authenticators.

### Non-goals

This proposal does *not* attempt to address any of the following:

* An algorithm is *discovered* to be unsafe, and the relying party would like to switch to a different algorithm without either having to trust the now untrusted algorithm once, or stepping the user up through some other authentication method. 
* An adversary develops an unknown capability to compromise an algorithm trusted by the relying party.

Relying parties interested in these advanced capabilities should consider using hybrid signature schemes instead. This proposal does not preclude the standardization of hybrid algorithms.

### Proposal

Just like in the Algorithm Policy proposal, we update the credential model to allow for multiple credentials per RP ID, user id, as long as they have a unique COSE algorithm.

A new assertion `createCredential` extension contains the necessary parameters to create a new credential.

```
dictionary AuthenticationExtensionsCreateCredentialInputs {
  required sequence<PublicKeyCredentialParameters> pubKeyCredParams;
  AuthenticationExtensionsClientInputs extensions;
}
```

On receiving this extension, a capable authenticator will examine the list of algorithms on `pubKeyCredParams`, finding the first algorithm it supports. If it matches the existing credential, the authenticator will complete the get assertion operation like usual. Otherwise, it will create a new credential with `extensions` and return it alongside the assertion with the old credential, in the *unsigned* extension outputs:

```
dictionary AuthenticationExtensionsCreateCredentialOutputs {
  // Create authenticator data.
  ArrayBuffer authenticatorData;

  // Extension outputs.
  AuthenticationExtensionsClientOutputs extensions;

  // List of credential IDs for this { RP ID, user ID } tuple.
  sequence<ArrayBuffer> existingCredentialIds;
};
```

The new credential will be stored alongside the old credential until the old credential is cleaned up.

In order to transfer trust to the new credential, the get assertion operation also includes a hash of the `authenticatorData` corresponding to the newly created credential in its *signed* extension outputs.

### Handling orphaned credentials in empty allow-list requests

Suppose an authenticator has a credential A. Later, a get assertion operation comes with a request to create a new credential B. The operation succeeds but the response doesn't make it to the server.

In that case, the relying party can compare the returned `existingCredentialIds` with its credential records, and send a new allow-list request for matching credentials.

### Cleaning up old credentials

The [Signal API](https://github.com/w3c/webauthn/blob/main/explainers/signal-api.md) was intended to be the way stale credentials are cleaned up from authenticators. Unfortunately, it doesn't work well with security keys, since security keys require passing user verification before allowing credential management commands. There's support to establish a persistent relationship between a client device and a security key at the FIDO level, but this hasn't been implemented (as far as I know) by any user agent, it requires consent from the user, and it requires the security key to be plugged in at the time the signal API request is received.

If we don't do anything, this proposal will end up littering authenticators with old credentials, and we don't want that. So we have a *companion* proposal: allow passing signal API requests alongside a regular WebAuthn request:

```
navigator.credentials.get({
  publicKey: {
    signalAllAcceptedCredentials: {
      rpId: "example.com",
      userId: "M2YPl-KGnA8",  // b64-url
      allAcceptedCredentialIds: [
        "vI0qOggiE3OT01ZRWBYz5l4MEgU0c7PmAA",  // b64-url
        ...
      ],
    },
    signalCurrentUserDetails: {
       rpId: "example.com",
       userId: "M2YPl-KGnA8",  // b64-url
       name: "a.new.email.address@example.com",
       displayName: "J. Doe"
    },
    challenge: [...],
  }
});
```

The advantage of using this form of the signal API is that it should work well with security keys. The user agent can obtain a PinUvAuthToken to clean up outdated credentials or change the user's name and display name. There is the clear disadvantage that it doesn't work for empty allow-list (usernameless) flows, since the relying party needs to pass the full list of credential IDs alongside the `get` request. Perhaps this is the feature that will push user agents to support persistent PinUvTokens.

Signal operations would behave exactly as they do normally, that is, there would be no confirmation of their success.

### Comparison with the Algorithm Policy proposal

#### Lack of algorithm groups and `acceptedAlgs`

The Algorithm Policy proposal has the relying party passing a list of groups of accepted algorithms (`createAlgs`) instead of a flat list, and allowing the relying party to say which algorithms they prefer (`acceptedAlgs`). The idea is that if an algorithm is *discovered* to be unsafe by the relying party, the relying party can switch to a previously created, still trusted algorithm. This switch does not require the relying party to trust the now untrusted algorithm.

Notably, this provides no protection against an adversary exploiting a previously unknown vulnerability in the most preferred algorithm, and it leaves the relying party vulnerable from the time of discovery to the time of patching their servers.

We posit that a rational relying party interested in addressing the first requirement must necessarily desire to address the second requirement. Hybrid algorithm schemes solve both, without needing to encumber the WebAuthn specification with more complexity. Importantly, hybrid algorithm schemes also solve those two problems independently of this proposal. With the staggering laundry list of changes necessary for WebAuthn to be fully migrated to PQC, independent changes are very attractive from a change management perspective.

#### Lack of confirmation for deleted credentials

The Algorithm Policy proposal proposes passing a list of credentials to be deleted (`deleteCredentials`) alongside the `get` request and returning a list of `deletedCredentials`. As far as I can see, there is no use for the list of `deletedCredentials`. `deleteCredentials` only works for allow-list requests.

Leveraging the signal API lets us decouple cleaning up credentials from supporting the migration. Relying parties, authenticators, and user agents can apply the same algorithms we are already using.

#### Returning new credentials as `authenticatorData`

The Algorithm Policy proposal indicates the returned credential as a `AuthenticatorAttestationResponseJSON` object plus a signed hash of the credential ID and selected algorithm. This seems strange, since not every relying party may want to serialize the response to JSON, e.g. they may send CBOR down the wire instead.

This proposal instead reuses the same algorithms we already use for the make credential operation, passing the CBOR `authenticatorData` and hashing it directly. `authenticatorData` already includes all the signed extension outputs, which are included in the data signed by the existing credential.
