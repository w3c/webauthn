# Explainer: WebAuthn raw signing extension

## Authors

- Emil Lundberg <[emil@yubico.com](mailto:emil@yubico.com)>

## Participate

- [Issue tracker](https://github.com/w3c/webauthn/pull/2078)

## Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Explainer: WebAuthn raw signing extension](#explainer-webauthn-raw-signing-extension)
  - [Authors](#authors)
  - [Participate](#participate)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [User-Facing Problem](#user-facing-problem)
    - [Goals](#goals)
    - [Non-goals](#non-goals)
  - [User research](#user-research)
  - [Proposed Approach](#proposed-approach)
    - [Dependencies on non-stable features](#dependencies-on-non-stable-features)
  - [Alternatives considered](#alternatives-considered)
    - [WebCrypto](#webcrypto)
    - [Adapting verifiers to support WebAuthn signatures](#adapting-verifiers-to-support-webauthn-signatures)
    - [Separate Parameter for Signing Key UV Policy](#separate-parameter-for-signing-key-uv-policy)
  - [Accessibility, Internationalization, Privacy, and Security Considerations](#accessibility-internationalization-privacy-and-security-considerations)
    - [Privacy Considerations](#privacy-considerations)
    - [Security Considerations](#security-considerations)
      - [Separation of Parent and Signing Keys](#separation-of-parent-and-signing-keys)
      - [Attestation and User Presence/Verification](#attestation-and-user-presenceverification)
  - [Stakeholder Feedback / Opposition](#stakeholder-feedback--opposition)
  - [References \& acknowledgements](#references--acknowledgements)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Introduction

This extension allows for signing arbitrary data using a key associated with
but different from a WebAuthn credential key pair.
This differs from a WebAuthn assertion signature,
which signs not over the challenge parameter provided by the RP or client,
but over the concatenation of authenticator data and a hash of a JSON object embedding that challenge.
In contrast, signatures returned from this extension are made over the given input unaltered.

The signing key pair is distinct from its parent WebAuthn credential key pair,
so this arbitrary input cannot be used to bypass the domain binding restrictions for WebAuthn credentials.

This extension would enable web applications to exercise hardware-bound keys in arbitrary cryptographic protocols,
similar to hardware cryptography providers such as OpenPGP or PKCS #11
that are available only to native client applications.

## User-Facing Problem

Web applications today have little access to hardware-backed cryptography.
Native applications can integrate with a wide variety of cryptographic hardware
via protocols such as PKCS #11, OpenPGPCard or simply USB,
which enables many high-security applications such as digital identity systems (e.g. [BankID][bankid]),
software package signing (e.g., [OpenPGP][openpgp]), user authentication (e.g. [OpenSSH][openssh])
and cryptocurrency wallets (e.g. Bitcoin).
These use cases benefit from hardware-backed cryptography
either as a user preference for greater assurance that one's keys cannot feasibly be copied,
or as required by law for regulated industries such as online banking.

These hardware capabilities are not currently available to web applications.
Some applications such as [BankID][bankid] work around this using a companion native application
which servers can communicate with directly, out-of-band from the web context.
This can be a problem for users not authorized to install software,
or if the native application is not well supported on the user's client platform.

Web applications do have access to some cryptography features via the [Web Cryptography (WebCrypto) API][webcrypto],
but this API abstracts over the implementation backend and provides no way for the web application
to discover security properties such as key protection measures of WebCrypto keys.
Conversely the [Web Authentication (WebAuthn) API][webauthn-3] does expose security properties
via its "authenticator attestation" features,
but WebAuthn signatures are strictly bound to the WebAuthn context
and therefore are not interchangeable with signatures created by other means such as OpenPGP or WebCrypto.

Proposals such as [WebUSB][webusb] or [Web Bluetooth][webbl] could in principle
provide access to hardware cryptography devices,
but in practice many security-oriented devices in particular are excluded from these APIs by [blocklists][webusb-blocklist].
This is because direct access to them could otherwise enable malicious web applications
to bypass security assumptions elsewhere, such as in WebAuthn.

The ability to sign arbitrary data with hardware-bound keys
would enable authoring web applications that can participate in any kind of cryptographic protocol based on signatures,
such as presenting digital identity documents or signing software releases or authorization tokens.

### Goals

- Enable use of **attested**, **hardware-bound** signing keys for **arbitrary** applications,
  including digital identity wallets and similar verifiable credentials. (Client-RP layer)

  - **Arbitrary** signatures:
    Signatures that are made directly over unaltered input data from the calling web application,
    as opposed to WebAuthn signatures which incorporates the application's `challenge` input
    into a particular data structure which is then signed.

  - **Hardware-bound** keys:
    Keys that are not exposed to the JavaScript runtime,
    or possibly (depending on implementation) not present in host memory at all.

    For example, keys may be held in a secure enclave or by a detachable USB security key.

    Hardware binding is not required; different implementations may leave different guarantees about key storage.
    Implementations can assert their guarantees, if any, via _attestation_.

  - **Attestation** of key properties:
    Provide a way for web applications to obtain verifiable assurance of key properties.

    Most notably, an attestation statement may be signed with a hardware vendor's attestation private key
    and assert that a newly generated key is hardware-bound and non-exportable,
    and possibly what hardware model it is bound to.

- Enable using FIDO security keys (possibly unattended) for general-purpose digital signatures,
  with seamless interoperability with existing cryptographic protocols. (Client-authenticator layer)

  This layer is not exposed to web applications, but is exhaustively specified for broad interoperability
  and may be used as a back-end for other cryptography features.

### Non-goals

- Support "**transaction confirmation**": A guarantee that before the signature was created,
  the data to be signed was displayed to the user in some trusted UI.

  This proposal assumes the data to be signed is opaque binary data unsuitable for display to humans,
  and does not require the client to display the data to be signed in any way.

  Alternative approaches such as the [WebAuthn `txAuthSimple` extension][txAuthSimple]
  could in principle be used together with this extension,
  but have so far [failed to gain implementation support][webauthn-delete-unimpl].
  This is in large part due to concerns that a "trusted UI"
  cannot feasibly display arbitrary unstructured data in any way
  that is intelligible to end-users while not susceptible to UI redressing attacks.
  If a similar proposal gains support in the future,
  it can be used to add on transaction confirmation signals to signatures created by this proposed extension
  since this extension's signature outputs are part of the signed authenticator data.

## User research

No user research has been performed.

## Proposed Approach

A WebAuthn extension with two operations:

- Generate a new key pair for one of some given signature algorithms,
  and return the public key and optionally an attestation statement.

- Sign arbitrary data given as a client extension input with a previously generated private key,
  and return the signature as a client extension output (for easy access)
  and authenticator extension output (for forward-compatibility with possible future transaction confirmation features).

Specification progress:

- Spec: https://yubicolabs.github.io/webauthn-sign-extension/
- Sources: https://github.com/yubicolabs/webauthn-sign-extension/
- Pull request: https://github.com/w3c/webauthn/pull/2078

Much like the `pubKeyCredParams` parameter in WebAuthn credential,
the extension has a `generateKey.algorithms` parameter for algorithm negotiation.
The algorithm of the signing key pair MAY be different from the algorithm of the parent WebAuthn credential.

Much like the credential ID of WebAuthn credentials,
the extension allows authenticators to store signing key material in an external "key handle"
in order to not consume storage space internally in the authenticator.
This enables authenticators to support unlimited numbers of signing key pairs.

The extension includes an `additionalArguments` field which can be used to convey additional inputs to the signing procedure
beyond the private key and data to be signed.
The format of this parameter is defined in the Internet-Draft [Split signing algorithms for COSE][cose-split-algs],
depends on the algorithm of the signing key,
and is extensible to support addition of future signature algorithms without changes to this extension API.
A motivating example for the design is [ARKG][arkg],
which enables efficient generation of unlinkable key pairs and requires two additional arguments `kh` and `ctx`.

Example:

```js
const pkc = await navigator.credentials.create({
    publicKey: {
        extensions: {
            previewSign5: {
                generateKey: {
                    // Signature algorithms ordered most to least preferred
                    algorithms: [
                        -300, // ESP256-split (PRELIMINARY; see https://www.ietf.org/archive/id/draft-lundberg-cose-two-party-signing-algs-06.html )
                        -9,   // ESP256
                    ],
                },
            },
        },
        authenticatorSelection: {
          // If "required", the signing key will ALWAYS require UV.
          // Otherwise the signing key MAY be used with or without UV.
          userVerification: "required",
        },

        // Core WebAuthn boilerplate below
        challenge: new Uint8Array([0]), // Will not be used in this example
        rp: { name: 'WebAuthn sign extension example' },
        user: {
            id: new TextEncoder().encode('4e5894c3-06fb-49be-8016-a4c8561e8298'), // Random UUID
            name: 'alice@example.org',
            displayName: 'Alice',
        },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], // ECDSA on P-256 with SHA-256; will not be used in this example
    },
});
const extensionResults = pkc.getClientExtensionResults();

const tbs = new TextEncoder().encode('Example data to be signed');
const assertion = await navigator.credentials.get({
    publicKey: {
        allowCredentials: [{ type: 'public-key', id: pkc.rawId, transports: pkc.response.getTransports() }],
        extensions: {
            previewSign5: {
                signByCredential: {
                    [pkc.id]: {
                        keyHandle: extensionResults.previewSign5.generatedKey.keyHandle,
                        tbs: (
                            extensionResults.previewSign5.generatedKey.algorithm === -300
                                ? await crypto.subtle.digest('SHA-256', tbs)
                                : tbs
                        ),
                    },
                },
            },
        },
        userVerification: "required", // As required by policy set at creation time

        // Core WebAuthn boilerplate below
        challenge: new Uint8Array([0]), // Will not be used in this example
    },
});

const assertionExtensionResults = assertion.getClientExtensionResults();

// Verify the signature using WebCrypto; this requires a few format conversions
const signatureDer = new Uint8Array(assertionExtensionResults.previewSign5.signature);
const signatureLen1 = signatureDer[3];
const signatureLen2 = signatureDer[4 + signatureLen1 + 1];
const signatureRaw = new Uint8Array([
    // Convert signature from DER encoding to fixed-length raw encoding
    // DER structure is: SEQUENCE tag (1+1 bytes), INTEGER (1+1+L1 bytes), INTEGER (1+1+L2 bytes)
    ...signatureDer.slice(4, 4 + signatureLen1).slice(Math.max(0, signatureLen1 - 32)),
    ...new Uint8Array(Math.max(0, 32 - signatureLen1)),
    ...signatureDer.slice(4 + signatureLen1 + 2).slice(Math.max(0, signatureLen2 - 32)),
    ...new Uint8Array(Math.max(0, 32 - signatureLen2)),
]);

const pkCose = new Uint8Array(extensionResults.previewSign5.generatedKey.publicKey);
const pkRaw = new Uint8Array([
    // Convert public key from COSE encoding to fixed-length raw encoding
    // CTAP2 canonical CBOR guarantees entries are in the order:
    // kty (1+1 bytes), alg (1+1 bytes), crv (1+1 bytes), x (1+2+32 bytes), y (1+2+32 bytes)
    0x04,
    ...pkCose.slice(10, 10 + 32),
    ...pkCose.slice(10 + 32 + 1 + 2),
]);
const publicKey = await crypto.subtle.importKey("raw", pkRaw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
const signatureOk = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signatureRaw, tbs);
console.log({ signatureOk });
```

### Dependencies on non-stable features

- [Split signing algorithms for COSE][cose-split-algs]:
  Defines the `COSE_Sign_Args` data structure of the `additionalArguments` parameter,
  as well as additional COSE algorithm identifiers including ESP256-split (-300) used in the example above.
  Split algorithm identifiers enable signing large payloads without having to send the full payload to the authenticator.
  This makes it feasible to sign large payloads using CTAP authenticators.

  For example: as seen in the above example,
  with ESP256-split (-300) the data to be signed is hashed by the RP and only the hash is sent to the authenticator,
  while with ESP256 (-9) the full data to be signed is sent to the authenticator which computes the hash internally.


The following is not a required dependency,
but is closely related as a motivating use case for the extension:

- [The Asynchronous Remote Key Generation (ARKG) algorithm][arkg]:
  defines a key generation algorithm that enables generating public keys on demand,
  without granting access to the corresponding private keys.
  Also defines (currently placeholders for) COSE algorithm identifiers for signing with ARKG-generated keys.

  In the context of this extension, this enables the RP to autonomously generate public keys without a WebAuthn invocation,
  while a WebAuthn invocation is required in order to generate signatures for any of those public keys.
  This enables use cases such as generating large batches of unlinkable single-use keys for key binding of digital credentials.

## Alternatives considered

### WebCrypto

The [Web Cryptography (WebCrypto) API][webcrypto] is arguably a more appropriate place than WebAuthn
for generating signatures over arbitrary data.
In fact, the client-to-authenticator layer of this proposal could in principle be used without modification
to implement a storage backend for WebCrypto keys.
Of particular note is the [Remote CryptoKeys][remote-cryptokeys] proposal,
which has similar goals of preventing private key material from being exposed to JavaScript.

We decided against proposing this as a WebCrypto feature for the following reasons:

- **Origin-bound keys.**
  The "sign" extension inherits the origin binding from WebAuthn,
  thus preventing signing keys from becoming a cross-origin user tracking handle.
  WebCrypto has no such origin binding.
  Remote CryptoKeys recommends, but does not require, that keys be scoped to a particular web origin.

- **Fixed key capabilities.**
  To prevent downgrade-style attacks, the "sign" extension fixes the capabilities of keys
  (specifically: whether the key requires UP/UV) at creation time.
  Remote CryptoKeys recommends, but does not require, some unspecified access control,
  and `getRemoteKey()` presumably allows accessing the same key with different `keyUsages` arguments.
  Perhaps individual key store implementations could forbid this,
  but that's a very weak promise for the API as a whole in that case.
  Especially without attestation, which is the next point.

- **Attestation.**
  This is the really big one - support for hardware attestation will be required
  if the API is to be used for things like (inter)national digital identity wallets.
  The "sign" extension supports this in much the same way as the top-level WebAuthn attestation,
  and the attestation signs over the fixed key capabilities described above.
  The Web Crypto API is not well equipped to convey hardware attestation information to the RP,
  and this is also missing from the current Remote CryptoKeys proposal.

- **Interoperability.**
  The "sign" extension defines an explicit interop protocol (on top of CTAP) between client and authenticator,
  so there's a concrete path for authenticator vendors to implement these features
  and have them work in any browser that supports the extension.
  Remote CryptoKeys only vaguely suggests that
  "[the key store] may be a secure key store, password manager, USB or BlueTooth device, etc."
  but makes no attempt to define an interface for it, let alone require some minimal interop profile,
  so compatibility is certain to differ between browsers.
  This might even be one of the [Non-Goals](https://github.com/WebKit/explainers/tree/main/remote-cryptokeys#non-goals),
  depending on interpretation that section.

Another powerful benefit of doing this in WebAuthn instead,
with algorithm identifiers etc. sent to and interpreted only by the authenticator,
is that authenticators can introduce support for new algorithms without the client explicitly supporting it.
For example, we (Yubico) want to be able to create signatures
using a key derived by [ARKG](https://yubico.github.io/arkg-rfc/draft-bradleylundberg-cfrg-arkg.html).
In the "sign" extension this only needs a new `COSEAlgorithmIdentifier` value understood by both the RP and the authenticator,
no change to the client is needed.
The same applies to, for example, introducing different elliptic curves or PQC algorithms.
With WebCrypto, all these things would need standardizing new `AlgorithmIdentifier` values/subtypes
and waiting for all relevant browsers to implement them.

### Adapting verifiers to support WebAuthn signatures

Instead of adding the capability to WebAuthn to generate signatures compatible with existing cryptographic protocols,
the opposite approach would be to adapt protocols and verifier implementations to be compatible with WebAuthn signatures.
For example, [OpenSSH 8.2][openssh-8.2] introduced support for using FIDO U2F and CTAP2 security keys as SSH keys.

This works, but the obvious drawback is that this requires implementation effort
for each protocol and verified that needs to be adapted.
The `sign` extension proposal is a drop-in replacement designed to be compatible with any existing cryptographic protocol
without additional implementation effort on the verifier side.

Another drawback of this approach is that it reuses WebAuthn credential keys for multiple purposes.
This is not necessarily a problem, but it increases the risk of protocol confusion attacks
where a signature indended for one use is repurposed for a different use.
It is therefore good security hygiene to use different cryptographic keys for different purposes.

### Separate Parameter for Signing Key UV Policy

When creating a signing key pair, the `userVerification` argument of the parent WebAuthn credential
also sets the UV policy for the created signing key.
The extension could have its own `userVerification` parameter
to set the UV policy of the signing key independently from the UV requirement of the ceremony.
Such a decoupling was judged not useful enough to be worth introducing an additional parameter
and opportunities for confusing it with the parent `userVerification` parameter.

The client-to-authenticator layer does have a separate `flags` parameter for the UP/UV policy of the signing key pair.

## Accessibility, Internationalization, Privacy, and Security Considerations

This extension prescribes no additional client UI,
so we do not anticipate any new accessibility or internationalization concerns
beyond those inherited from WebAuthn.

### Privacy Considerations

Being a WebAuthn extension, this proposal inherits the privacy considerations from WebAuthn
and MUST NOT undermine any of WebAuthn's privacy promises.
In particular:

- The proposal SHALL NOT introduce cross-origin user tracking handles.
- The proposal SHALL NOT introduce ways to de-anonymize users without consent.

Both of these goals are mostly covered by WebAuthn already:
signing keys are created and used by WebAuthn registration and authentication ceremonies,
and therefore the origin binding and user consent limitations of WebAuthn apply also to signing keys.

The client-to-authenticator layer does allow for generating signing keys that can be used without a test of user presence (UP),
but this option is not exposed through the WebAuthn layer.
This mirrors how FIDO CTAP2 allows `authenticatorGetAssertion` (UP) while WebAuthn does not.
Thus native client applications can create and use unattended signing keys,
but web applications cannot bypass the prompt for user consent.

Signing keys could become cross-origin user tracking handles
if authenticator implementations somehow reuse keys between origins,
for example by always generating the same keypair in every key generation operation.
Like for top-level WebAuthn credentials, such implementations should be considered faulty and non-compliant.

### Security Considerations

#### Separation of Parent and Signing Keys

Since signing keys can sign over arbitrary RP-chosen input,
it is critical that signing keys are not the same keys as their parent WebAuthn credential keys.
Exposing WebAuthn credential keys as arbitrary signing keys
would allow malicious RPs to bypass most of WebAuthn's security guarantees
by requesting signatures over WebAuthn assertion data.
Therefore all signing key pairs are distinct from and cryptographically unrelated to their parent WebAuthn credential key.
This prevents protocol confusion attacks from using the extension to obtain valid WebAuthn assertions for the parent credential.

#### Attestation and User Presence/Verification

Since signing keys do not sign over an authenticator data structure,
they cannot convey attributes such as user presence (UP) and user verification (UV) flags
in the signatures they produce.
Therefore unlike their parent WebAuthn credentials,
signing keys have a UP and UV policy set at creation time and fixed for the lifetime of the key.
The policy defines the minimum requirements for any ceremony where that signing key is used.
Thus a verifier that has received a valid attestation statement for a signing key pair
can be assured that that signing key pair cannot be downgraded to more permissive ceremony requirements.

## Stakeholder Feedback / Opposition

Client implementors:

- Chrome: No signals
- Firefox: No signals
- Safari: No signals
- Edge: No signals

Authenticator implementors:

- Yubico: [Positive](https://www.yubico.com/blog/yubico-will-introduce-secure-and-privacy-capable-passkey-enabled-digital-signatures-in-upcoming-5-8-firmware/)

RP implementors:

- [wwWallet][wwWallet]: [Positive](https://github.com/wwWallet/wallet-frontend/pull/1025)

## References & acknowledgements

Many thanks for valuable feedback and advice from:

- John Bradley
- Kostas Georgantas
- Michael B. Jones
- Klas Lindfors
- Ludvig Michaelsson
- Nina Satragno
- Orie Steele

Thanks to the following proposals, projects, libraries, frameworks, and languages
for their work on similar and related problems that influenced this proposal.

- [OpenSK](https://github.com/google/OpenSK/)
- [wwWallet][wwWallet]


[arkg]: https://datatracker.ietf.org/doc/draft-bradleylundberg-cfrg-arkg/10/
[bankid]: https://www.bankid.com/
[cose-split-algs]: https://www.ietf.org/archive/id/draft-lundberg-cose-two-party-signing-algs-06.html
[openpgp]: https://datatracker.ietf.org/doc/rfc9580/
[openssh-8.2]: https://www.openssh.org/txt/release-8.2
[openssh]: https://www.openssh.org/
[remote-cryptokeys]: https://github.com/WebKit/explainers/tree/main/remote-cryptokeys
[txAuthSimple]: https://www.w3.org/TR/webauthn-1/#sctn-simple-txauth-extension
[webauthn-3]: https://www.w3.org/TR/webauthn-3/
[webauthn-delete-unimpl]: https://github.com/w3c/webauthn/issues/1386
[webbl]: https://webbluetoothcg.github.io/web-bluetooth/
[webcrypto]: https://w3c.github.io/webcrypto/
[webusb-blocklist]: https://github.com/WICG/webusb/blob/main/blocklist.txt
[webusb]: https://wicg.github.io/webusb/
[wwWallet]: https://github.com/wwWallet/
