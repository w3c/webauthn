# Explainer: WebAuthn PRF Extension

Security keys are physical devices, often USB-connected, that can create public–private key pairs and sign with the private keys to authenticate a user. Websites can use them via the [WebAuthn API](https://www.w3.org/TR/webauthn-2/). Several major sites allow users to register security keys for better account security, for example, Microsoft, Dropbox, GitHub, Google, and Facebook, to name a few.

There are several cases where sites would like to combine authentication and release of a secret key. Any site that wants to do end-to-end encryption needs to store key material somewhere, and since security keys are high-security enclaves, several inquiries have been made about whether a WebAuthn assertion could also contain key material.

The underlying protocol for security keys, CTAP2, includes [an optional extension](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-hmac-secret-extension) (`hmac-secret`) to facilitate this. It was originally designed to enable security keys to decrypt local storage when signing into a computer (i.e. not for a web context) but it exposes a generic pseudo-random function that is useful for lots of things.

A psuedo-random function (PRF) is a function that is externally indistinguishable from a random oracle for a computationally-bound attacker. A [random oracle](https://en.wikipedia.org/wiki/Random_oracle) is a function like this:

```py
oracle_outputs = {}
def random_oracle(x):
  if x not in oracle_outputs:
    value = generate_random_output()
    oracle_outputs[x] = value

  return oracle_outputs[x]
```

Concretely, HMAC with a random key and strong hash function is a practical PRF.

The WebAuthn [`prf` extension](https://w3c.github.io/webauthn/#prf-extension) allows sites to request that a WebAuthn authenticator create a PRF along with a credential and allows sites to query that PRF during assertions. Since this extension can be implementing by using the CTAP2 `hmac-secret` extension, and because many security keys support that, it should immediately have quite wide support. (At least in the subset of users who use security keys.)

The most basic pattern of use would be to request the evaluation of a fixed value in every assertion. I.e. request the evaluation of &ldquo;end-to-end encryption key&rdquo; every time. That will cause WebAuthn assertions, where supported, to contain a per-credential, 32-byte secret key that can be used for that purpose with, for example, the WebCrypto API.

The API also supports more complex uses by allowing each assertion to query the PRF at two inputs. This allows for automatic key rotation if the server generates random evaluation points by getting a "current" and "next" encryption key with each assertion, and rotating the evaluation points over time.

In order that exposing the outputs of the `hmac-secret` extension to the web not invalidate the security assumptions of any non-web users, the PRF evaluation points are hashed with a fixed prefix before use to partition the PRF space. (Assuming that an attacker cannot calculate preimages for SHA-256.)

### Example

The following example reflects the basic usage of the PRF extension where a fixed key is requested per credential. It requests a PRF evaluation from a discoverable credential bound to the current origin and logs it to the console, base64 encoded. It requires a security key that supports the `hmac-secret` feature in CTAP2. (See sample below to create a credential first if the origin doesn't already have one.)

```js
navigator.credentials.get({
    publicKey: {
        timeout: 60000,
        challenge: new Uint8Array([ 
            // must be a cryptographically random number sent from a server. Don't use dummy
            // values in real authentication situations.
            1,2,3,4,
        ]).buffer,
        extensions: {prf: {eval: {first: new TextEncoder().encode("Foo encryption key")}}},
    },
}).then((c) => {
  console.log(btoa(String.fromCharCode.apply(null, new Uint8Array(
                c.getClientExtensionResults().prf.results.first))));
});
```

Rather than logging to the console, a real use might decrypt some saved state with the resulting key. For example, by using [AES-GCM with WebCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt). Since the key will be constant for a given credential, it's vitally important to ensure the the nonce used when encrypting is unique. Since users may have multiple credentials, a two-level encryption structure may be needed to allow decryption with any of their security keys. But the design of such structures is out of scope here.

If you need to set up a credential to try that example, the following snippet will do that:

```js
navigator.credentials.create({
    publicKey: {
        rp: {name: "Acme"},
        user: {
            id: new Uint8Array(16),
            name: "john.p.smith@example.com",
            displayName: "John P. Smith"
        },
        pubKeyCredParams: [{type: "public-key", alg: -7}],
        timeout: 60000,
        authenticatorSelection: {
            authenticatorAttachment: "cross-platform",
            residentKey: "required",
        },
        extensions: {prf: {}},

        // unused without attestation so a dummy value is fine.
        challenge: new Uint8Array([0]).buffer,
    }
}).then((c) => {console.log(c.getClientExtensionResults());});
```

### Privacy

Nothing in this extension changes the general privacy properties of WebAuthn. Thus the PRFs are always per-credential and cannot be used to correlate anything between different credentials. Evaluating the PRFs is done in the context of an assertion and so a human will see the usual WebAuthn UI and will need to tap a security key (or approve in UI for platform authenticators) before any information is released.

Access control is enforced based on [RP ID](https://www.w3.org/TR/webauthn-2/#rp-id) and so origins that are authorised to get an assertion from a credential are also authorised to evaluate any PRFs. WebAuthn works in cross-site iframes if the parent frame explicitly [permits it](https://w3c.github.io/webauthn/#sctn-permissions-policy) with Permissions Policy, thus this extension can work in that context too. The cross-origin iframe would still be limited by the [RP ID mechanism](https://w3c.github.io/webauthn/#rp-id) so that it could only attempt to assert credentials created within the same eTLD+1, however.

A PRF value could be used as a tracking vector, but that would be a bit obtuse because WebAuthn credentials themselves already have a large random ID.

Fundamentally, as an authentication mechanism WebAuthn must be a method of identification. The balance is that WebAuthn requires a ceremony: browser UI plus authenticator activation (e.g. touching a security key). The PRF extension is part of a WebAuthn authentication and thus requires the same ceremony, it can never be triggered silently or the like.
