# Explainer: WebAuthn Algorithm Policy (PQC Migration & Cryptographic Agility)

## Authors

Akshay Kumar \<[akshayku@microsoft.com](mailto:akshayku@microsoft.com)\>

*Last updated: 29th July, 2026*

## Contents

- [Explainer: WebAuthn Algorithm Policy (PQC Migration \& Cryptographic Agility)](#explainer-webauthn-algorithm-policy-pqc-migration--cryptographic-agility)
  - [Authors](#authors)
  - [Contents](#contents)
  - [Summary](#summary)
  - [Design goals](#design-goals)
  - [Proposal](#proposal)
    - [1. Multiple credentials per `(rpId, user.id)`](#1-multiple-credentials-per-rpid-userid)
    - [2. The `preferredAlgs` request option and the `algPolicy` extension on `get()`](#2-the-preferredalgs-request-option-and-the-algpolicy-extension-on-get)
      - [Behavior at `get()` time](#behavior-at-get-time)
    - [3. RP-side handling](#3-rp-side-handling)
  - [Security considerations](#security-considerations)
  - [Privacy considerations](#privacy-considerations)

## Summary

This proposal helps Relying Party (RP) to evaluate different signature algorithms and migrate its
users between them *during the normal authentication ceremony*,
without forcing users through an explicit re-enrollment flow and
without putting accounts at risk of lockout while the transition is in progress.

This proposal is flexible and algorithm agnostic although it is addressing current need for such
migration of users passkeys from classical algorithms (ECDSA/RSA etc) to PQC algorithms (ML-DSA etc)
and having emergency fallbacks to classical algorithm if needed.

## Design goals

* **No explicit re-enrollment ceremony.**
  * Migration happens opportunistically during ordinary `get()` flows.
* **No window of lockout.**
  * Authenticator MUST have atleast one credential that user can use to authenticate with the RP.
* **Algorithm-agnostic.**
  * The mechanism must be reusable for any future algorithm transition, not hard-coded to PQC.
* **Backwards-compatible.**
  * Clients, authenticators, and RPs that do not understand the extension continue to work
    as they do today.

## Proposal

### 1. Multiple credentials per `(rpId, user.id)`

The authenticator credential model is udpated so that an authenticator can store more than one
discoverable credential for the same `(rpId, user.id)` pair, **subject to the invariant that
no two such credentials use the same COSE algorithm**.
That is, the unique key becomes `(rpId, user.id, alg)` rather than `(rpId, user.id)`.

### 2. The `preferredAlgs` request option and the `algPolicy` extension on `get()`

The authentication-time policy is exposed at two layers, matching the things they actually do:

* **`preferredAlgs`**
  * This is a new top-level member on `PublicKeyCredentialRequestOptions` (and the JSON variant).
  * This is a preference-ordered list of COSE algorithms for this authentication ceremony.
  * It **orders** which credential is used when an account has more than one; it does not exclude
    credentials. The RP still verifies the returned assertion's algorithm server-side.
* **`algPolicy`** extension
  * **`createAlgs`**
    * A single preference-ordered list of COSE algorithms. The authenticator creates the
      best one it supports that the account does not already hold.
  * **`createExtensions`**
    * Extensions if new credentials are being created while evaluating the `createAlgs`
  * **`deleteCredentials`**
    * Credential IDs that should be deleted from the authenticator in case of orphan credentials.
    * This is needed because `signalUnknownCredential` API cannot reach roamable authenticators.

`createAlgs` governs which credentials **exist**; `preferredAlgs` governs which is **preferred** for a
ceremony. To retire an algorithm, the RP drops it from `preferredAlgs` (so a still-present credential of
another algorithm is preferred instead) and rejects it server-side. A classical credential that exists
but is left out of `preferredAlgs` is a dormant break-glass fallback: it adds no standing risk while the
RP prefers and accepts only the strong algorithm, yet can be relied on immediately if that algorithm
must be retired — without re-enrollment.

```webidl
partial dictionary PublicKeyCredentialRequestOptions {
  //
  // COSE algorithm identifiers the RP prefers for this assertion, in RP's
  // preference order (most preferred first). Orders, but does not restrict,
  // the discoverable-credential candidate set.
  //
  sequence<COSEAlgorithmIdentifier> preferredAlgs;
};

partial dictionary PublicKeyCredentialRequestOptionsJSON {
  sequence<COSEAlgorithmIdentifier> preferredAlgs;
};

partial dictionary AuthenticationExtensionsClientInputs {
  AuthenticationExtensionsAlgPolicyInputs algPolicy;
};

dictionary AuthenticationExtensionsAlgPolicyInputs {
  //
  // A single preference-ordered list of COSE algorithms, most-preferred first.
  //
  // Let B be the earliest algorithm in this list the authenticator supports.
  // If none is supported, nothing is created (not a failure).
  // If a credential using B already exists for (rpId, user.id), nothing is created.
  // Otherwise the authenticator MAY create exactly one new credential using B.
  //
  // At most one credential is created per ceremony. To also provision a fallback (or a
  // second algorithm), the RP issues a follow-up get() whose createAlgs best-supported
  // entry is the next algorithm it wants (see RP-side handling).
  //
  // At most 32 algorithms may be listed; a longer list is rejected with a TypeError.
  //
  // The empty array is VALID: enumerate-only mode, where the RP wants the signed
  // existingCredentials (and any deletedCredentials) snapshot without creating a credential.
  //
  required sequence<COSEAlgorithmIdentifier> createAlgs;

  //
  // Extension inputs applied to every credential silently created in this ceremony.
  // It has the same dictionary input as the `extensions` member on
  // `PublicKeyCredentialCreationOptions`, and processed by the authenticator identically
  // to how `create()` would process them.
  //
  // This lets the RP evaluate extensions (for example PRF) on silently-created
  // credentials.
  //
  AuthenticationExtensionsClientInputs createExtensions;

  //
  // A list of credential IDs the RP asks the SELECTED authenticator to DELETE during this ceremony.
  //
  // This MUST be used with a single `allowCredentials` credential.
  // Let's call this credential as anchor credential for this ceremony.
  //
  // The authenticator MUST delete a listed credential ID ONLY when it
  // resides on the authenticator AND is bound to the SAME
  // (rpIdHash, user.id) as the credential being asserted in this ceremony
  // (the anchor). IDs that do not exist, or that belong to a different RP
  // or a different user.id, are silently ignored — they are never deleted
  // and never cause the assertion to fail. Deletion is authorized by the
  // ceremony's user verification plus the anchor assertion (proof the RP
  // controls a co-resident credential for this account);
  //
  // Processed BEFORE `createAlgs` creation in this same ceremony, so a credential just
  // deleted can be re-created in one gesture. The set of IDs actually deleted is reported
  // in the SIGNED `deletedCredentials` output.
  //
  sequence<BufferSource> deleteCredentials;
};

partial dictionary AuthenticationExtensionsClientOutputs {
  AuthenticationExtensionsAlgPolicyOutputs algPolicy;
};

dictionary AuthenticationExtensionsAlgPolicyOutputs {
  //
  // The unsigned extension outputs (from createExtensions) of the credential created this
  // ceremony, if any. The created credential's authenticatorData — carrying its credential ID
  // and public key — is in the signed `createdCredentialAuthData` output, read from the
  // assertion's authenticatorData.
  //
  AuthenticationExtensionsClientOutputs createdCredentialExtensionOutputs;
};
```


#### Behavior at `get()` time

When `preferredAlgs` is present (with or without the `algPolicy` extension):

1. **Establish user verification first, then discover.** User verification
   is performed *before* the applicable-credential set is computed.
   With UV established, the platform / authenticator performs the usual
   credential discovery for `rpId`.
   * `preferredAlgs` does not remove any credential from the candidate set;
     it only orders selection (below).
   * `preferredAlgs` is only applicable to authenticators which
     support multi credential per RPID/UserID model.
2. If the candidate set is empty the platform behaves as today (no
   credentials available → `NotAllowedError` after the normal UI timeout /
   cancel). An empty set never results from `preferredAlgs`.
3. The platform / authenticator selects a credential for assertion, over
   the post-UV candidate set.
   * When multiple credentials are available for the same `(rpId, user.id)`, the
     platform/authenticator **collapses the account to a single representative** — the
     one whose `alg` is **earliest in `preferredAlgs`**. A credential whose `alg` is not in
     `preferredAlgs` ranks below any that is; if none is listed, the authenticator picks by its
     own preference.
4. **Delete Credentials.**
   * If the request carries `algPolicy.deleteCredentials` and there is no allowlist, return `TypeError`.
   * The authenticator deletes each listed credential ID if it satisfies following conditions
     * Credential resides on **this** authenticator and
     * Credential is bound to the **same `(rpId, user.id)`** as the credential being asserted (the anchor).
   * Save the deleted credential IDs to be emitted in the signed `deletedCredentials` set.
5. **Create Credential.**
   * If `createAlgs` is **empty**, skip this step.
   * Let `B` be the **earliest entry in `createAlgs` this authenticator supports**. If none is
     supported, create nothing (not a failure).
   * If a credential using `B` already exists for `(rpId, user.id)`, create nothing.
   * Otherwise the authenticator **MAY** create one fresh **discoverable** credential using `B` for the
     same `(rpId, user.id, user.name, user.displayName)` as the anchor, applying any `createExtensions`
     as if passed to `navigator.credentials.create()`.
     * The created credential's `authenticatorData` is emitted in the signed `createdCredentialAuthData`
       output; its unsigned extension outputs are emitted in the unsigned output.
   * Creation is **opportunistic**: the authenticator MAY decline (resource constraints) and MUST NOT
     fail the assertion for it. The RP may create it on a later ceremony.
6. **Populate existingCredentials**
   * After deletion and creation step, enumerate all the credentials `(rpId, user.id)` and
     save their credential in `existingCredentials` set
7. **Populate the algPolicy extension output.**
   * Signed output — a CTAP CBOR map in the assertion's `authenticatorData`:
   ```cddl
   algPolicy = {
     1: [* bstr],   ; existingCredentials — all credential IDs held for (rpId, user.id). Always present.
     2: [* int],    ; supportedAlgs — COSE algorithms this authenticator supports. Always present.
     ? 3: bstr,     ; createdCredentialAuthData — authenticatorData of the credential created this
                    ;   ceremony. Omitted when nothing was created.
     ? 4: [* bstr], ; deletedCredentials — credential IDs actually deleted. Omitted when none.
     ? 5: uint,     ; maxCredentialsPerAccount — per-(rpId, user.id) cap, if the authenticator has one.
   }
   ```
     Because the created credential's `authenticatorData` rides in this signed map, the asserting
     credential's signature vouches for the new credential's ID and public key.
   * Unsigned output: the created credential's unsigned extension outputs (e.g. PRF), surfaced to the
     RP as `createdCredentialExtensionOutputs`.

### 3. RP-side handling

Throughout the code samples below, algorithms are referred to by their canonical names
(`ML-DSA-87`, `ML-DSA-65`, `ES256`, `RS256`, etc.) via a placeholder `alg` lookup object
(e.g. `alg["ML-DSA-65"]`).
The normative numeric COSE codepoints live in the IANA
[COSE Algorithms registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).

Example usernameless authentication request:

```js
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge,
    rpId: "example.com",
    userVerification: "preferred",
    // Top-level: RP prefers any ML-DSA variant (preferring -87), then ECC, then RSA
    // in that preference order.
    preferredAlgs: [
      alg["ML-DSA-87"],
      alg["ML-DSA-65"],
      alg["ML-DSA-44"],
      alg["ES384"],
      alg["ES256"],
      alg["RS256"],
    ],
    extensions: {
      algPolicy: {
        // Single preference list. The authenticator creates the best algorithm it supports
        // that this account does not already hold — here a PQC credential.
        createAlgs: [
          alg["ML-DSA-87"],
          alg["ML-DSA-65"],
          alg["ML-DSA-44"],
        ],
        // Extension inputs applied to every silently-created credential.
        // Same shape as `extensions` on create().
        createExtensions: {
          // e.g. prf: {} ...
        },
      },
    },
  },
});

// The signed algPolicy map is read from the assertion's authenticatorData.
const { existingCredentials, supportedAlgs, createdCredentialAuthData, maxCredentialsPerAccount }
  = rp.algPolicyFromAuthData(assertion);
const ext = assertion.getClientExtensionResults().algPolicy;

// Register the newly created credential. Its ID and public key come from the signed
// createdCredentialAuthData, so trust is inherited from the assertion signature that covers it.
if (createdCredentialAuthData) {
  await rp.registerCreatedCredential(
    account, createdCredentialAuthData, ext?.createdCredentialExtensionOutputs);
}

// Optional fallback: if the created credential is pure PQC and the authenticator also supports a
// classical algorithm, provision a dormant classical credential in a follow-up ceremony. Kept out
// of `preferredAlgs` in steady state, it adds no standing risk but can be relied on if the PQC
// algorithm must be retired.
const createdAlg = rp.algOf(createdCredentialAuthData);
const classicalAlgs = [alg["ES384"], alg["ES256"], alg["RS256"]].filter(a => supportedAlgs.includes(a));
const hasHeadroom = maxCredentialsPerAccount === undefined
  || existingCredentials.length < maxCredentialsPerAccount;
if (createdAlg && !rp.isHybrid(createdAlg) && classicalAlgs.length && hasHeadroom) {
  await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: "example.com",
      allowCredentials: [{ type: "public-key", id: assertion.rawId }],  // re-target THIS authenticator
      userVerification: "required",
      extensions: { algPolicy: { createAlgs: classicalAlgs } },
    },
  });
  // Register the fallback credential as above.
}

// Orphan delete: any credential ID the authenticator holds for this account that the RP does not
// recognize is an orphan — typically from a prior create whose upload failed. Deleting it lets a
// fresh create take its place.
const knownIds = new Set(await rp.getCredentialIds(account));
const orphanIds = existingCredentials.filter(
  (id) => id !== assertion.id && !knownIds.has(id));

if (orphanIds.length > 0) {
  const anchorId = existingCredentials.find((id) => knownIds.has(id));
  const isAuthenticatorReachable = assertion.authenticatorAttachment == "internal";

  if (isAuthenticatorReachable) {
    // Gesture-free background cleanup.
    for (const id of orphanIds) {
      await PublicKeyCredential.signalUnknownCredential({
        rpId: "example.com",
        credentialId: id,
      });
    }
  } else if (anchorId !== undefined) {
    // In-line deletion: recognized anchor in allowlist, orphans in deleteCredentials.
    await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: "example.com",
        allowCredentials: [{ type: "public-key", id: anchorId }],  // re-targets THIS device
        userVerification: "required",
        extensions: {
          algPolicy: {
            deleteCredentials: orphanIds,  // pruned on this authenticator only
            createAlgs: [alg["ML-DSA-87"], alg["ML-DSA-65"], alg["ML-DSA-44"]],  // re-create in place
          },
        },
      },
    });
    // Register any created credential as above.
  }
}
```

## Security considerations

* **In-ceremony creation re-uses the assertion's user verification.**
  * The UV gesture authorizes the whole ceremony's scope (this user, this RP, this moment)
    and newly created keys are explicitly vouched for by the existing registered user credential.
    Hence, reusing user verification is safe here.
* **Asserter-binding of the created credential.**
  * The created credential's `authenticatorData` — carrying its credential ID and public key — is
    placed in the signed `createdCredentialAuthData` output, and the assertion signature covers
    `authData`. So the new credential is authenticated by the asserting credential, one the RP
    already trusts in this ceremony.
  * Any party that can mutate the response in transit (a compromised extension or platform component,
    an unauthenticated authenticator-to-host transport, a malicious script) cannot change the created
    credential's ID or public key without breaking the assertion signature.
  * The RP **MUST** read the created credential from the signed output, not from any unsigned data.
* **Inline deletion (`deleteCredentials`) considerations**
  * **Inline deletion cannot delete a credential the RP did not point at.**.
    * A listed ID is deleted **only** when it 
      * Credential resides on the selected authenticator
      * Credential is bound to the same `(rpIdHash, user.id)` as the anchor
        credential asserted in the same ceremony, under that ceremony's user verification.
    * If credentialIDs in `deleteCredentials` are absent, or scoped to another RP or another `user.id`
      than the assertion credentials userid, then those credential IDs are silently ignored.
  * **User is never stranded**
    * User is always able to sign-in to the account as asserting credential is always present
      and never deleted. Hence, authenticator will always have atleast one credential to login the user
      to the account.
  * **The orphan-identification list may be unverified, but it cannot cause  wrongful deletion.**
    * In the worst orphan case the *asserting* credential is itself the orphan,
      its `existingCredentials` list rides under a signature the RP cannot verify
      (it has no public key for that credential).
      The RP nonetheless reads that list to pick a recognized credential as an *anchor*.
    * A forged or tampered list cannot escalate, because:
      * The RP only ever places unrecognized IDs in `deleteCredentials`, never an ID it recognizes,
        so a good credential is never targeted.
      * The authenticator deletes only IDs that actually exist under the
        anchor's `(rpIdHash, user.id)`, so injected fake IDs are no-ops.
      * The recovery ceremony is independently authenticated by the anchor credential's
        *verifiable* signature.
    * The worst outcome of tampering is a no-op or an incomplete delete (the orphan simply resurfaces
      and is deleted next time) — never the loss of a credential the RP still relies on.
* **Attestation conveyance is fixed at `"none"`.**
  * The created credential carries no attestation statement; provenance against in-transit
    substitution comes from the asserter-binding above. RPs that require an attested statement can
    obtain one via an explicit `create()`.
* **Counter and clone-detection.**
  * Each credential keeps its own signature counter. Counters of distinct credentials
    are unrelated and MUST NOT be compared.

## Privacy considerations

* The extension introduces no new identifier beyond what `create()` already returns: new public
  keys and per-credential random credential IDs.
* `supportedAlgs` reports the algorithms the authenticator supports. This is already discoverable via
  attestation plus the FIDO Metadata Service and via CTAP `authenticatorGetInfo`. It is returned to an
  RP the user has already registered with, is low-entropy (shared across a product line), and does not
  enable cross-RP correlation.
* As with `excludeCredentials`, an RP could probe algorithm support via repeated `create()` calls;
  `supportedAlgs` exposes no more than that.
