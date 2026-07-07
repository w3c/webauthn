# Explainer: WebAuthn Algorithm Policy (PQC Migration & Cryptographic Agility)

## Authors

Akshay Kumar \<[akshayku@microsoft.com](mailto:akshayku@microsoft.com)\>

*Last updated: 7th July, 2026*

## Contents

- [Explainer: WebAuthn Algorithm Policy (PQC Migration \& Cryptographic Agility)](#explainer-webauthn-algorithm-policy-pqc-migration--cryptographic-agility)
  - [Authors](#authors)
  - [Contents](#contents)
  - [Summary](#summary)
  - [Design goals](#design-goals)
  - [Proposal](#proposal)
    - [1. Multiple credentials per `(rpId, user.id)`](#1-multiple-credentials-per-rpid-userid)
    - [2. The `acceptedAlgs` request option and the `algPolicy` extension on `get()`](#2-the-acceptedalgs-request-option-and-the-algpolicy-extension-on-get)
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

### 2. The `acceptedAlgs` request option and the `algPolicy` extension on `get()`

The authentication-time policy is exposed at two layers, matching the things they actually do:

* **`acceptedAlgs`**
  * This is a new top-level member on `PublicKeyCredentialRequestOptions` (and the JSON variant).
  * This is a preference-ordered list of COSE algorithms that are valid for this authentication ceremony.
  * This list is used to filter credentials and selecting which credential should be used to authenticate
    and complete the authentication ceremony.
* **`algPolicy`** extension
  * **`createAlgs`**
    * This contains COSEAlgorithmIdentifier for what kind of credentials authenticator
      should hold.
  * **`createExtensions`**
    * Extensions if new credentials are being created while evaluating the `createAlgs`
  * **`deleteCredentials`**
    * Credential IDs that should be deleted from the authenticator in case of orphan credentials.
    * This is needed because `signalUnknownCredential` API cannot reach roamable authenticators.

```webidl
partial dictionary PublicKeyCredentialRequestOptions {
  //
  // COSE algorithm identifiers the RP is willing to accept for this assertion,
  // in RP's preference order (most preferred first).
  // Used both to filter the discoverable-credential candidate set.
  //
  sequence<COSEAlgorithmIdentifier> acceptedAlgs;
};

partial dictionary PublicKeyCredentialRequestOptionsJSON {
  sequence<COSEAlgorithmIdentifier> acceptedAlgs;
};

partial dictionary AuthenticationExtensionsClientInputs {
  AuthenticationExtensionsAlgPolicyInputs algPolicy;
};

dictionary AuthenticationExtensionsAlgPolicyInputs {
  //
  // A list of algorithm groups where each algorithm group is a preference-ordered list of
  // COSE algorithms, most-preferred first.
  // RP wants authenticator to create best supported credential from each group.
  //
  // For each group, the authenticator first identifies the BEST algorithm it supports.
  // Let's call that algorithm B.
  //
  // A group is SATISFIED iff an authenticator has an existing B algorithm credential
  // for (rpId, user.id).
  // If no entry in the group is supported, then the group is UNSATISFIABLE
  // on this authenticator and is ignored (not a failure).
  //
  // For each UNSATISFIED group, the authenticator MAY create one new
  // credential using algorithm B and return it in the extension output.
  //
  // At most THREE groups may be listed.
  // The max number of algorithms RP can specify each group is 32 algorithms.
  // The client rejects a get() whose createAlgs has more than three groups or any group
  // having more than 32 algorithms with a TypeError.
  //
  // The empty array (zero groups) is VALID entry: It is the
  // enumerate-only mode, where the RP wants the signed
  // existingCredentials (and any deletedCredentials) snapshot without
  // provisioning a new credential. Valid range is 0..3 groups inclusive.
  // The member is `required` so that presence of the algPolicy extension always carries
  // an explicit (possibly empty) group list rather than an undefined one.
  //
  required sequence<sequence<COSEAlgorithmIdentifier>> createAlgs;

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
  // Processed BEFORE `createAlgs` creating in this same ceremony, so a
  // group whose only credential was just deleted is re-opened and can be
  // re-created in one gesture. The set of IDs actually deleted is reported
  // back in the SIGNED `deletedCredentials` output.
  //
  sequence<BufferSource> deleteCredentials;
};

partial dictionary AuthenticationExtensionsClientOutputs {
  AuthenticationExtensionsAlgPolicyOutputs algPolicy;
};

dictionary AuthenticationExtensionsAlgPolicyOutputs {
  //
  // Zero or more new credentials created during this ceremony, one entry
  // per `createAlgs` group the authenticator chose to satisfy.
  //
  sequence<AuthenticatorAttestationResponseJSON> createdCredentials;
};
```


#### Behavior at `get()` time

When `acceptedAlgs` is present (with or without the `algPolicy` extension):

1. **Establish user verification first, then discover.** User verification
   is performed *before* the applicable-credential set is computed.
   With UV established, the platform / authenticator performs the usual 
   credential discovery for `rpId` and filters the candidate set to credentials
   whose `alg` appears in the top-level `acceptedAlgs`.
   * If `allowCredentials` is also present, it is intersected as today; the
     `acceptedAlgs` filter is additive.
   * If `acceptedAlgs` is absent, no algorithm filter is applied and the
     candidate set is whatever discovery (and `allowCredentials`)
     produces, exactly as today.
   * `acceptedAlgs` filter is only applicable to authenticators which
     support multi credential per RPID/UserID model.
2. If the candidate set is empty the platform behaves as today (no
   credentials available → `NotAllowedError` after the normal UI timeout /
   cancel).
3. The platform / authenticator selects a credential for assertion, over
   the post-UV candidate set.
   * When multiple credentials are available for the same `(rpId, user.id)`, the
     platform/authenticator **collapses the account to a single representative** — the
     one whose `alg` is **earliest in `acceptedAlgs`**
4. **Delete Credentials.**
   * If the request carries `algPolicy.deleteCredentials` and there is no allowlist, return `TypeError`.
   * The authenticator deletes each listed credential ID if it satisfies following conditions
     * Credential resides on **this** authenticator and
     * Credential is bound to the **same `(rpId, user.id)`** as the credential being asserted (the anchor).
   * Save the deleted credential IDs to be emitted in the signed `deletedCredentials` set.
5. **Create Credentials.**
   * If `createAlgs` is **empty**  (zero groups), skip this credential creation step.
   * Authenticator iterates the groups in order. For each group `g`:
     * Let `B` be the **earliest entry in `g` that this authenticator
       supports**. If no entry in `g` is supported, the group is
       **unsatisfiable** and is skipped (not a failure).
     * If there exists a credential under `(rpId, user.id)` with algorithm
       `B`, the group is **satisfied** and the authenticator does nothing
       for it.
     * Otherwise, the group is **unsatisfied**.
       The authenticator MAY create a fresh **discoverable** credential using algorithm `B` for the same
       `(rpId, user.id, user.name, user.displayName)` — copying the user entity stored with
       the asserting credential
       `algPolicy.createdCredentials`.
       * Calculate `credHash` for this credential and save it to the `mintHashes` set
          ```
          credHash = SHA-256( credIdLen || credId || COSE_Key )
          ```
       * At most one credential is created per group per ceremony.
       * Any `createExtensions` inputs are applied to the create as if they had been passed to
       `navigator.credentials.create()`.
       * Calculate the authenticatorMakeCredential response and save in `createdCredentials` set.
     * The authenticator **MAY** leave any subset of unsatisfied groups unfilled (including all of them)
       based on local resource constraints (storage, keygen latency, transport MTU, battery).
       * It **MUST** prefer filling groups that appear earlier in `createAlgs` when filling
         only a subset.
       * It **MUST NOT** fail the assertion because it could not fill a group.
   * The RP **MUST** treat `createdCredentials` as opportunistic.
     Any group not filled in this response may be filled on a subsequent ceremony.
     The RP must not depend on full coverage from a single response.
6. **Populate existingCredentials**
   * After deletion and creation step, enumerate all the credentials `(rpId, user.id)` and
     save their credential in `existingCredentials` set
7. **Populate signed and unsigned algPolicy Extension output.**
   * `"algPolicy"` Authenticator signed extension CTAP CBOR map output:
   ```cddl
   algPolicy = {
     1: [* bstr],   ; "existingCredentials" set — the full set of credential
                    ; IDs the authenticator holds for (rpId, user.id).
                    ; Always present (at minimum the asserting credential's ID).
     2: [* bstr],   ; "mintHashes" set — one credHash per credential created.
                    ; A signed SET whose membership authenticates each create.
                    ; Omitted when nothing was created.
     3: [* bstr],   ; "deletedCredentials" set — the credential IDs actually
                    ; deleted as part of extension processing.
                    ; Signed so that the RP can trust the delete completed.
                    ; Omitted when nothing was deleted.
   }
   ```
   * `"algPolicy"` Authenticator unsigned extension CTAP CBOR output:
     * Authenticator Extension Output
       * Authenticator emits `createdCredentials` set as CTAP array in `algPolicy` key identified
         extension in unsignedExtensions (0x08).
   * `"algPolicy"` Client Extension Output
     * Client converts above CBOR array of `createdCredentials` to
       `AuthenticatorAttestationResponseJSON` output.

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
    // Top-level: RP currently accepts any ML-DSA variant (preferring -87), and ECC, and RSA
    // in that preference order.
    acceptedAlgs: [
      alg["ML-DSA-87"],
      alg["ML-DSA-65"],
      alg["ML-DSA-44"],
      alg["ES384"],
      alg["ES256"],
      alg["RS256"],
    ],
    extensions: {
      algPolicy: {
        // RP wants every account to hold one PQC credential and one classical fallback.
        // Each group is ordered strongest-first.
        // The authenticator creates the best algorithm it supports in each group.
        createAlgs: [
          [
            alg["ML-DSA-87"],
            alg["ML-DSA-65"],
            alg["ML-DSA-44"]
          ],
          [
            alg["ES384"],
            alg["ES256"],
            alg["RS256"]
          ],
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

const ext = assertion.getClientExtensionResults().algPolicy;

// Register any new credentials the authenticator just created in this ceremony,
// after verifying the asserter-binding for each one.
// `registerAdditionalCredential` parses the `algPolicy` authenticator-extension output
// in `assertion.response.authenticatorData`, computes
// credHash = SHA-256(credIdLen || credId || COSE_Key) from createdCredentials attested
// credential data, and refuses to persist the createdCredential
// unless that credHash is a member of the signed `mintHashes` set.
for (const created of ext?.createdCredentials ?? []) {
  await rp.registerAdditionalCredential(account, assertion, created);
}

// Orphan delete: Any credential ID the authenticator holds for this account but that the RP does
// not recognize is an orphan — typically from a prior `createdCredentials` upload that failed.
// Deleting it re-opens the corresponding `createAlgs` group for a fresh create.
// `existingCredentialsFromAuthData` parses key 1 of the `algPolicy` map in
// `assertion.response.authenticatorData`.
const existingIds = rp.existingCredentialsFromAuthData(assertion);
const knownIds = new Set(await rp.getCredentialIds(account));
const orphanIds = existingIds.filter(
  (id) => id !== assertion.id && !knownIds.has(id));

// Orphan Credential Cleanup.
if (orphanIds.length > 0) {
  // Find a credential that is recognizable to the RP.
  const anchorId = existingIds.find((id) => knownIds.has(id));
  // Is Authenticator reachable silently
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
    // In-line deletion using recognized credential in allowlist and unrecognized credentials
    // in deleteCredentials list.
    const recovery = await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: "example.com",
        allowCredentials: [{ type: "public-key", id: anchorId }],  // re-targets THIS device
        userVerification: "required",
        extensions: {
          algPolicy: {
            deleteCredentials: orphanIds,   // pruned on this authenticator only
            createAlgs,                     // re-create the reopened groups
          },
        },
      },
    });
    // Persist any fresh `createdCredentials` as in the block above.
  }
}
```

## Security considerations

* **In-ceremony creation re-uses the assertion's user verification.**
  * The UV gesture authorizes the whole ceremony's scope (this user, this RP, this moment)
    and newly created keys are explicitly vouched for by the existing registered user credential.
    Hence, reusing user verification is safe here.
* **Asserter-binding of silently-created credentials.**
  * For every entry the authenticator places in `createdCredentials`, it also places a
    matching `credHash` in the signed `mintHashes` set in
    `authData.extensions.algPolicy`, where
  `credHash = SHA-256(credIdLen ‖ credId ‖ COSE_Key)`.
  * The assertion signature covers `authData`, so these hashes are cryptographically
    authenticated by the asserting credential — a credential the RP
    already trusts in this ceremony.
  * Any party that can mutate `createdCredentials` in transit (a compromised browser extension, a
    compromised platform component, an unauthenticated authenticator-to-host transport,
    a malicious script between the JS context and the RP) therefore cannot substitute
    attacker-controlled public keys (or swap the credential ID or algorithm) into the upload
    without also forging a matching `credHash`, which it cannot do without the asserting
    credential's private key.
  * The RP **MUST** discard any entry in `createdCredentials` whose `credHash` is not a member
    of the signed set.
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
  * Any entry returned in  `createdCredentials` carries the same `AuthenticatorAttestationResponse`
    shape as `navigator.credentials.create()` would have produced, but the
    attestation statement is always none. Provenance against in-transit substitution is supplied
    by the asserter-binding the newly created credential.
    RPs that require attested statement for every credential can do so via explicit `create()`.
* **Counter and clone-detection.**
  * Each credential keeps its own signature counter. Counters of distinct credentials
    are unrelated and MUST NOT be compared.

## Privacy considerations

* The extension does not introduce any new identifier visible to the RP
  beyond what `create()` already returns: the RP learns one or more new
  public keys and credential IDs, all of which are per-credential random
  values.
* The extension does not reveal which algorithms the authenticator
  supports beyond the ones it actually mints. An authenticator that
  cannot satisfy any entry in a `createAlgs` group simply omits an output
  for that group; it does not enumerate its capabilities or report which
  group entries it skipped or why.
* As with the existing `excludeCredentials` discussion, an RP could
  attempt to use distinct `acceptedAlgs` / `createAlgs` to probe what
  algorithms an authenticator supports. The information leak is no
  greater than the one already possible via successive `create()` calls
  with varying `pubKeyCredParams`.
