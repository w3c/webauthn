# Explainer: WebAuthn Algorithm Policy (PQC Migration & Cryptographic Agility)

## Authors

Akshay Kumar \<[akshayku@microsoft.com](mailto:akshayku@microsoft.com)\>

*Last updated: 2026-06-09*

## Contents

- [Explainer: WebAuthn Algorithm Policy (PQC Migration \& Cryptographic Agility)](#explainer-webauthn-algorithm-policy-pqc-migration--cryptographic-agility)
  - [Authors](#authors)
  - [Contents](#contents)
  - [Summary](#summary)
  - [Background and motivation](#background-and-motivation)
  - [Design goals](#design-goals)
  - [Proposal](#proposal)
    - [1. Multiple credentials per `(rpId, user.id)`](#1-multiple-credentials-per-rpid-userid)
    - [2. The `acceptedAlgs` request option and the `algPolicy` extension on `get()`](#2-the-acceptedalgs-request-option-and-the-algpolicy-extension-on-get)
      - [Behavior at `get()` time](#behavior-at-get-time)
      - [CTAP mapping](#ctap-mapping)
    - [3. RP-side handling](#3-rp-side-handling)
      - [Operational guidance for RPs](#operational-guidance-for-rps)
      - [PRF and `hmac-secret` on silently-minted credentials](#prf-and-hmac-secret-on-silently-minted-credentials)
    - [4. Selection and pruning on the authenticator / OS](#4-selection-and-pruning-on-the-authenticator--os)
    - [5. Authenticator capability and fallback](#5-authenticator-capability-and-fallback)
  - [Recommended configuration for RPs](#recommended-configuration-for-rps)
    - [Strategy 1 — Explicit fallback (pure PQC + classical)](#strategy-1--explicit-fallback-pure-pqc--classical)
    - [Strategy 2 — Composite / hybrid (single credential)](#strategy-2--composite--hybrid-single-credential)
      - [Strategy 2 - Homogeneous Fleet Configuration](#strategy-2---homogeneous-fleet-configuration)
      - [Strategy 2 - Heterogeneous Fleet Configuration](#strategy-2---heterogeneous-fleet-configuration)
  - [Worked examples](#worked-examples)
    - [Worked example A: forward migration (ECDSA → ML-DSA)](#worked-example-a-forward-migration-ecdsa--ml-dsa)
    - [Worked example B: emergency downgrade](#worked-example-b-emergency-downgrade)
    - [Worked example C: a new PQC family arrives (multi-family evaluation and migration)](#worked-example-c-a-new-pqc-family-arrives-multi-family-evaluation-and-migration)
  - [Security considerations](#security-considerations)
  - [Privacy considerations](#privacy-considerations)
  - [Interaction with other features](#interaction-with-other-features)
  - [Open questions](#open-questions)
  - [Useful links](#useful-links)

## Summary

A migration story that lets a Relying Party (RP) move its passkey population
between signature algorithms — most urgently from a classical algorithm
(e.g. ECDSA/RSA/EdDSA) to a post-quantum algorithm (e.g. ML-DSA), and
later in either direction as cryptographic agility requires — *during the
normal authentication ceremony*, without forcing users through an explicit
re-enrollment flow and without putting accounts at risk of lockout while the
transition is in progress.

The proposal has three coupled pieces:

1. **Relax the authenticator credential model** so that an authenticator may
   hold **more than one discoverable credential per `(rpId, user.id)` pair**,
   provided each credential uses a *different* COSE algorithm.
2. **A new top-level `acceptedAlgs` member on
   `PublicKeyCredentialRequestOptions`** — a flat, preference-ordered
   list of COSE algorithms that governs which credentials are valid
   **right now** for authentication.
   * It is used to filter the discoverable-credential candidate set at
   `get()` time and also to choose among multiple credentials for the same
   account.
3. **A new `algPolicy` client extension on `navigator.credentials.get()`**
   that adds the silent-mint provisioning channel:
   * **`createAlgs`** — a list of **algorithm groups**, where each group
     is itself a preference-ordered list of COSE algorithm identifiers,
     strongest first. For each group, let *B* be the earliest entry in
     the group that the authenticator supports. A group is *satisfied*
     iff an existing credential under `(rpId, user.id)` uses algorithm
     *B*. On each successful assertion, for each unsatisfied group, the
     authenticator MAY silently mint one credential using *B* and
     return it alongside the assertion. Because *B* is recomputed
     against the authenticator's current capabilities every ceremony,
     a firmware update that adds a stronger algorithm re-opens the
     group and the authenticator self-upgrades on the next sign-in —
     no RP-side change required.
   * **Selection and convergence outputs.** This extension itself never
     deletes credentials. Old credentials no longer in `acceptedAlgs` are
     filtered out of the candidate set and sit dormant on the
     authenticator, available as cold fallback if the RP later widens
     its policy. The extension's output also includes the full list of
     credential IDs the authenticator holds for the account, so the RP
     can detect **orphan** credentials (credentials on the authenticator
     that the RP never received — e.g. from a failed
     `createdCredentials` upload) and sweep them by issuing
     `signalUnknownCredential`. Hygiene cleanup of dormant credentials
     and orphan sweep are both handled by the existing
     [Signal API](signal-api.md), which the RP calls post-ceremony by
     credential ID.

The two knobs answer different questions and move independently:
- `acceptedAlgs` governs which credentials are valid *right now* for authentication.
- `createAlgs` governs which credentials the authenticator *should hold*
  - The group structure of `createAlgs` lets the RP express
"give me the strongest one you can mint from this group" (e.g. any
ML-DSA variant, preferring the strongest the authenticator supports, or
ECC-preferred-with-RSA-fallback) without asking the authenticator to
mint every variant.
  - Each authenticator automatically converges to the
strongest entry it supports in each group, and re-converges automatically
if a firmware update later widens its algorithm support.

The decoupling lets the RP pre-provision fallback credentials *before* they are needed.

## Background and motivation

Passkeys have become a load-bearing authentication primitive for a growing
number of Relying Parties (RPs), and the cryptographic ground under them
is about to move. Various organization around the world has set concrete
deadlines for retiring classical signature algorithms in regulated
deployments well before cryptographically relevant quantum computers are
expected to arrive. Every RP that has deployed ECDSA / RSA / EdDSA
passkeys now owns a migration problem, and the WebAuthn / CTAP stack as
it exists today does not give them the tools to solve it without either
disrupting their users or accepting open-ended account-lockout risk.

This proposal exists because the current platform forces RPs into a set
of bad choices. Concretely:

* **The authenticator credential model allows only one credential per
  `(rpId, user.id)`.** Registering a new credential with the same
  `user.id` overwrites the existing one (per CTAP2.x "already exists"
  handling and the WebAuthn registration ceremony rules). So an RP that
  wants to add a PQC credential without removing the working classical
  one literally cannot — the data model does not represent that state.
  Migration today is therefore either an explicit re-enrollment ceremony
  for every user (disruptive, gated on a separate strong authentication,
  and effectively impossible to complete for the inactive long tail) or
  a destructive overwrite on next sign-in (any failure between "old key
  deleted on device" and "new public key durably stored at the RP" is an
  account lockout).

* **The authenticator fleet is heterogeneous and there is no single
  cutover date.** An RP's user population at any given moment spans
  many authenticator models, OS versions, and firmware revisions, with
  PQC support arriving incrementally over a period of years. Synced
  passkey providers can ship PQC support relatively quickly; roaming
  security keys are firmware-bound and a meaningful fraction of devices
  in the field will never receive a PQC update. There is no date on
  which the RP can simply switch `pubKeyCredParams` from ECDSA to
  ML-DSA and expect its users to follow. Any workable migration must
  proceed *per authenticator*, opportunistically, over the lifetime
  of the fleet.

* **There is no capability discovery.** WebAuthn gives the RP no way
  to ask, ahead of time, which authenticator user will select and what
  algorithms a given authenticator can generate.
  `pubKeyCredParams` is a one-shot negotiation evaluated
  inside a single `create()` ceremony; the RP learns what the
  authenticator could do only by attempting a registration and
  inspecting the resulting credential's `alg`. This makes it
  very hard to plan a rollout, size the PQC-capable population,
  pre-provision fallbacks selectively etc.

* **Algorithm policy is a registration-time decision, not an
  authentication-time one.** Today the RP expresses its algorithm
  preferences only at `create()`, via `pubKeyCredParams`. At `get()`
  there is no symmetric primitive — no protocol-level way to say
  "for this assertion I will accept ML-DSA but not ES256," to prefer
  one credential over another when several exist, or to signal that a
  given algorithm is being phased out. Algorithm policy is effectively
  frozen at the moment each credential was minted, which is exactly
  backwards for a multi-year agility story where the policy needs to
  evolve while the credential population catches up. This proposal
  fills the gap by adding a top-level `acceptedAlgs` member to
  `PublicKeyCredentialRequestOptions`, mirroring `pubKeyCredParams`
  at the same layer.

* **There is no graceful crypto-emergency story.** If a weakness is
  later disclosed in a deployed algorithm — whether classical or
  post-quantum — the RP's only lever today is to refuse the affected
  algorithm at `get()` and drive every affected user through
  re-enrollment by some out-of-band channel. There is no
  pre-provisioned, server-known fallback credential in a *different*
  algorithm sitting ready on the authenticator; there is no way for
  the RP to have arranged one in advance, because the one-credential
  data model does not allow it. A crypto break therefore becomes a
  mass account-recovery event rather than a configuration change.

Post-quantum migration is the immediate forcing function, but the same
shortcomings will recur at every future algorithm transition.
Cryptographic agility is a recurring operational need, not a one-time
event, and the mechanism designed for "classical ⇒ PQC" must equally
serve "ML-DSA-65 ⇒ ML-DSA-87", "MLDSA ⇒ next-PQC" and the emergency
downgrade "PQC ⇒ classical" direction.

The proposal in the rest of this document gives
RPs the three pieces they are missing
  * Multiple credentials per account on a single authenticator
  * An authentication-time algorithm policy
  * Opportunistic provisioning channel that converges the
fleet over time — so that migration becomes a configuration change the
RP rolls out at its own pace, with no re-enrollment ceremony and no
lockout window.

## Design goals

* **No explicit re-enrollment ceremony.** Migration happens opportunistically
  during ordinary `get()` flows.
* **No window of lockout.** The legacy credential remains usable until the
  new credential is verifiably accepted by the RP backend.
* **No authenticator left behind.** Authenticators that cannot
  generate PQC keys still keep working (they simply continue to assert with
  their existing credential as long as the RP accepts it).
* **Algorithm-agnostic.** The mechanism must be reusable for any future
  algorithm transition, not hard-coded to PQC.
* **Backwards-compatible.** Clients, authenticators, and RPs that do not
  understand the extension continue to behave as they do today.

## Proposal

### 1. Multiple credentials per `(rpId, user.id)`

The authenticator credential model is relaxed so that an authenticator
**may** store more than one discoverable credential for the same
`(rpId, user.id)` pair, **subject to the invariant that no two such
credentials use the same COSE algorithm**. That is, the unique key becomes
`(rpId, user.id, alg)` rather than `(rpId, user.id)`.

Each credential in the set is otherwise a normal WebAuthn credential: it has
its own credential ID, its own key pair, its own signature counter, its own
backup-eligibility / backup-state, and is independently subject to the
Signal API.

Authenticators that cannot or choose not to store more than one credential
per `(rpId, user.id)` continue to be conformant; they simply behave as they
do today and overwrite on conflict (see §"Authenticator capability and
fallback" below).

### 2. The `acceptedAlgs` request option and the `algPolicy` extension on `get()`

The authentication-time policy is exposed at two layers, matching the
things they actually do:

* **`acceptedAlgs`** is a new top-level member on
  `PublicKeyCredentialRequestOptions` (and the JSON variant). It is a
  preference-ordered list of COSE algorithms the RP will validate for
  this assertion. It is a plain platform-side candidate-set filter; it
  does not require the relaxed credential model of §1 and an RP may
  ship it on its own. It is the symmetric counterpart at `get()` of
  `pubKeyCredParams` at `create()`.
* **`algPolicy`** is a new client extension that carries the silent-mint
  provisioning machinery: `createAlgs` (which credentials the account
  should hold), `createExtensions` (extension inputs applied to silently
  minted credentials), and the output `createdCredentials`. The
  orphan-sweep list (`existingCredentials`) is **not** a client output;
  it is delivered only in the signed `authData` (see §2 steps 6–7). This
  extension depends on §1.

The two inputs are independent: `acceptedAlgs` governs *runtime*
behavior (which credentials are valid right now), and `createAlgs`
governs *provisioning* (which credentials the account should hold).
The extension outputs include both any newly-minted credentials and
the full list of credential IDs the authenticator currently holds for
this account — the latter lets the RP detect and sweep orphan
credentials so server-side and authenticator-side state stay in
convergence. The extension itself does not delete credentials; see
§4 "Selection and pruning" for the pruning model and for how the RP
uses the existing [Signal API](signal-api.md) for cleanup.

```webidl
partial dictionary PublicKeyCredentialRequestOptions {
  //
  // COSE algorithm identifiers the RP is willing to accept for this
  // assertion, in RP preference order (most preferred first). Used
  // both to filter the discoverable-credential candidate set and to
  // choose among multiple credentials for the same (rpId, user.id).
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
  // A list of algorithm groups the RP wants the account to hold
  // credentials in. Each outer entry is one group. Each group is a
  // preference-ordered list of COSE algorithms, most-preferred first.
  //
  // For each group, the authenticator first identifies the BEST entry it
  // supports — the earliest entry in the group whose algorithm this
  // authenticator can mint. Let's call that algorithm B.
  //
  // A group is SATISFIED iff an existing credential under
  // (rpId, user.id) uses algorithm B. If no entry in the group is
  // supported, the group is UNSATISFIABLE on this authenticator and is
  // ignored (not a failure).
  //
  // For each UNSATISFIED group, the authenticator MAY mint one new
  // credential using algorithm B and return it in the extension output.
  // Note that satisfaction is computed against B specifically, not
  // against "any algorithm in the group." This makes the rule
  // self-upgrading: if a firmware update later adds support for an
  // earlier-listed (stronger) algorithm, B advances, the group becomes
  // unsatisfied, and the upgrade happens automatically on the next
  // ceremony without any RP-side change.
  //
  // At most THREE groups may be listed. The client rejects a get() whose
  // createAlgs has more than three groups with a TypeError. Each group an
  // authenticator satisfies consumes one persistent credential slot.
  // The length of each group is unbounded — a group of any length mints
  // exactly one credential, so the cap is on the OUTER list only.
  //
  required sequence<sequence<COSEAlgorithmIdentifier>> createAlgs;

  //
  // Extension inputs applied to every credential silently created in this
  // ceremony. It has the same dictionary input as
  // the `extensions` member on `PublicKeyCredentialCreationOptions`,
  // and processed by the authenticator identically to how `create()`
  // would process them.
  //
  // This lets the RP evaluate extensions (for example PRF) on silently-minted
  // credentials. Without it, a silent mint produces a credential that
  // authenticates but lacks any extension-bound capability the RP relies on.
  //
  // NOTE on PRF: a silently-minted credential gets its own independent PRF
  // secret, so its PRF output differs from the asserting credential's. To
  // obtain that output in THIS ceremony (so the RP can re-wrap PRF-derived
  // data), the mint must evaluate PRF at makeCredential time.
  //
  AuthenticationExtensionsClientInputs createExtensions;
};

partial dictionary AuthenticationExtensionsClientOutputs {
  AuthenticationExtensionsAlgPolicyOutputs algPolicy;
};

dictionary AuthenticationExtensionsAlgPolicyOutputs {
  //
  // Zero or more new credentials minted during this ceremony, one entry
  // per `createAlgs` group the authenticator chose to satisfy. Order is
  // not guaranteed; the RP must inspect each entry's algorithm.
  //
  // On roaming authenticators these attestation objects are conveyed as
  // the UNSIGNED output of the algPolicy authenticator extension (the
  // `unsignedExtensionOutputs` field of the authenticatorGetAssertion
  // response), and authenticated by the signed {id, pkHash, alg}
  // bindings carried in authData.extensions. The public-key bytes travel
  // exactly once; the signed pkHash commits to them.
  //
  sequence<AuthenticatorAttestationResponseJSON> createdCredentials;
};
```

There is **no** `existingCredentials` member on this
client-output dictionary. The existing credentials list lives **only** in the
signed `authData.extensions.algPolicy` map as one source of truth. By
contrast, `createdCredentials` *is* a client extension output.
This is because of the fact that authenticatorMakeCredential output contains unsignedExtensions like PRF and that should not be signed over by the
authenticating credential. Newly created credentials are authenticated
indirectly by the signed `pkHash` bindings.

#### Behavior at `get()` time

When `acceptedAlgs` is present (with or without the `algPolicy`
extension):

1. The platform performs the usual credential discovery for `rpId`. The
   candidate set is filtered to credentials whose `alg` appears in the
   top-level `acceptedAlgs`.
   * If `allowCredentials` is also present, it is intersected as today; the
     `acceptedAlgs` filter is additive.
   * If `acceptedAlgs` is absent, no algorithm filter is applied and the
     candidate set is whatever discovery (and `allowCredentials`)
     produces, exactly as today.
2. If the candidate set is empty the platform behaves as today (no
   credentials available → `NotAllowedError` after the normal UI timeout /
   cancel).
3. The platform / authenticator selects a credential for assertion. When
   multiple credentials are available for the same `(rpId, user.id)`, the
   one whose `alg` is **earliest in `acceptedAlgs`** is preferred. This is
   selection, not user choice: from the user's point of view the multiple
   credentials are a single "account" — the algorithm is an implementation
   detail.
4. **Gather authorization once.** The authenticator collects user
   presence and (if required) user verification a single time. This one
   gesture authorizes *both* the assertion and any silent creations in
   step 5; no second prompt is shown. Note that this step only collects
   the user gesture — it does **not** yet produce the assertion
   signature. The signature is computed last (after steps 5–7), because
   it covers `authData`, and `authData` must already carry the binding
   entries (step 6) and `existingCredentials` (step 7), both of which
   depend on the mint in step 5 having already happened. The effective
   order within the ceremony is therefore: collect authorization (step
   4) → mint (step 5) → assemble `authData` with bindings +
   `existingCredentials` (steps 6–7) → sign `authData` and return the
   assertion.
5. **Silent in-ceremony creation.** If `createAlgs` is present, the
   client first validates it: a `createAlgs` with **more than three
   groups** is rejected with a `TypeError` before the ceremony proceeds
   (see *How many groups?* in §2). Otherwise the authenticator iterates
   the groups in order. For each group `g`:
   * Let `B` be the **earliest entry in `g` that this authenticator
     supports**. If no entry in `g` is supported, the group is
     **unsatisfiable** and is skipped (not a failure).
   * If an existing credential under `(rpId, user.id)` uses algorithm
     `B`, the group is **satisfied** and the authenticator does nothing
     for it.
     * Note: existing credentials using other algorithms in `g`
     (weaker entries that the authenticator also supports) do **not**
     satisfy the group. They remain valid for assertion under
     `acceptedAlgs` but do not block a stronger mint.
   * Otherwise, the group is **unsatisfied**. The authenticator MAY mint a
     fresh credential using algorithm `B` for the same
     `(rpId, user.id, user.name, user.displayName)`, including its
     `AuthenticatorAttestationResponse`-shaped output in
     `algPolicy.createdCredentials`. At most one credential is minted
     per group per ceremony. Any `createExtensions` inputs are applied
     to the mint as if they had been passed to
     `navigator.credentials.create()`; the corresponding extension
     outputs are included in the returned
     `AuthenticatorAttestationResponseJSON`.
   * No additional user gesture or UV prompt is required: the user has
     already authorized this ceremony, and the new credentials are bound
     to the same account they just proved control of.
   * Newly minted credentials do **not** replace the asserted credential or
     any other existing credential on the authenticator. All are retained.
   * The authenticator **MAY** leave any subset of unsatisfied groups
     unfilled (including all of them) based on local resource constraints
     (storage, keygen latency, transport MTU, battery). It **SHOULD**
     prefer filling groups that appear earlier in `createAlgs` when filling
     only a subset. It **MUST NOT** fail the assertion because it could
     not fill a group, and it **MUST NOT** evict an existing credential
     (under this `(rpId, user.id)` or any other) to make room for a
     silent create — storage pressure results in fewer fills, never in
     evictions.
   * The RP **MUST** treat `createdCredentials` as opportunistic. Any
     group not filled in this response may be filled on a subsequent
     ceremony; the RP must not depend on full coverage from a single
     response.
   * If the authenticator does not support the relaxed credential model
     (§1), it behaves as if every group were over-budget: it performs
     the assertion normally and returns an empty (or absent)
     `createdCredentials`.
6. **Emit asserter-binding entries in `authData`.** For each entry the
   authenticator added to `algPolicy.createdCredentials` in step 5, it
   **MUST** emit a corresponding *binding entry* in the `algPolicy`
   authenticator-extension output carried inside `authData.extensions`.
   Because the assertion signature covers `authData`, these binding
   entries are cryptographically authenticated by the asserted
   credential: any party that mutates `createdCredentials` between the
   authenticator and the RP cannot also forge a matching binding entry
   without the asserting credential's private key.

   The output is a CBOR map under the extension identifier `"algPolicy"`:

   ```cddl
   algPolicy = {
     1: [* bstr],            ; "existingCredentials" — the full set of
                             ; credential IDs the authenticator holds
                             ; for (rpId, user.id); see step 7. Always
                             ; present (at minimum the asserting
                             ; credential's ID).
     2: [* binding-entry],   ; "bindings" — one entry per credential
                             ; minted in step 5; empty when none were
                             ; minted, in which case this key MAY be
                             ; omitted.
   }

   binding-entry = {
     1: bstr,    ; "id"     — credential ID of the minted credential,
                 ;            verbatim, matching the `id` member of
                 ;            its `AuthenticatorAttestationResponseJSON`
                 ;            entry in `algPolicy.createdCredentials`.
     2: bstr,    ; "pkHash" — SHA-256 over the canonical CBOR encoding
                 ;            of the minted credential's COSE_Key
                 ;            public key (as it appears in the attested
                 ;            credential data of that entry's
                 ;            `authenticatorData`).
     3: int,     ; "alg"    — COSEAlgorithmIdentifier of the minted
                 ;            credential.
   }
   ```

   Both `bindings` and `existingCredentials` ride in the **signed**
   `authData.extensions`: the binding entries authenticate each minted
   public key, and `existingCredentials` is authenticated because it
   drives `signalUnknownCredential` (a *deletion*) on the RP side — a
   list an attacker could tamper with to suppress orphan detection or
   provoke spurious sweeps if it were unsigned. Integer map keys are
   used for on-the-wire compactness. Both the top-level map and each
   `binding-entry` are **extensible**: future revisions of this
   extension MAY define additional integer keys for new fields, and
   verifiers **MUST** ignore unknown keys to preserve
   forward-compatibility.

   The RP **MUST** verify, before persisting any entry in
   `createdCredentials`, that there is a binding entry in
   `authData.extensions.algPolicy.bindings` whose `id` matches the
   entry's credential ID, whose `pkHash` matches SHA-256 of the
   canonical CBOR encoding of the entry's COSE public key, and whose
   `alg` matches the entry's algorithm. Entries without a matching
   binding **MUST** be discarded. See §3 "RP-side handling" for the
   complete flow, and "Asserter-binding of silently-minted credentials"
   in Security considerations for the threat model this closes.

   **How the public key reaches the RP (roaming authenticators).** The
   binding entry above is only a *commitment* — `pkHash` is a digest, not
   the key. The minted credential's actual public key must still travel
   from the authenticator to the client, and on a roaming security key
   that means it must be carried in the `authenticatorGetAssertion`
   response over CTAP. It is carried as the **unsigned** output of the
   `algPolicy` authenticator extension — i.e. in the
   `unsignedExtensionOutputs` field of the assertion response (CTAP map
   key `0x08`), *not* in the signed `authData` — as a list of
   `attestationObject`s (`fmt: "none"`, `authData` with attested
   credential data, empty `attStmt`), one per credential minted in step 5.
   The client surfaces them as the `AuthenticatorAttestationResponse`-shaped
   entries in `algPolicy.createdCredentials`. `algPolicy` therefore has
   **two** authenticator-extension outputs working as a pair: a small
   **signed** output (the `{id, pkHash, alg}` bindings in
   `authData.extensions`, integrity-protected by the assertion signature)
   and a larger **unsigned** output (the attestation objects in
   `unsignedExtensionOutputs`, carrying the public-key bytes). The RP
   recomputes SHA-256 over each conveyed COSE public key and matches it
   against the signed `pkHash`, so the unsigned payload inherits the
   signed commitment's integrity without itself being signed.

   This split is deliberate and is the minimum-size design. The public
   key is **irreducible**: there is no way for the RP to learn a freshly
   minted public key without those bytes transiting the assertion
   response — for ML-DSA that is ~1.3 KB (-44) to ~2.6 KB (-87) per
   credential. The split avoids paying that cost *twice*: signing the
   key into `authData` would duplicate every public-key byte under the
   signature (and re-impose a canonical-encoding burden on the RP),
   whereas a 32-byte `pkHash` authenticates the same payload at fixed
   cost. Fixing attestation at `"none"` keeps `attStmt` empty, so the
   only large object on the wire is the public key itself. A constrained
   authenticator that cannot afford multiple groups simply mints fewer groups
   (it **MUST NOT** fail the assertion), and the remaining groups
   are filled on later sign-ins.

   Beyond size, the split also respects what the minted output *is*: by
   CTAP's own model it is an **unsigned** `makeCredential` result
   (`fmt: "none"`, empty `attStmt`), produced by a `makeCredential`
   nested inside the `getAssertion`. It also has unsigned extension output
   like PRF. Embedding it in the assertion's signed `authData` would mean
   copying an unsigned-by-design artifact into the signed region.
   The two-channel split keeps it in its natural unsigned home and
   lets it inherit integrity from the signed `pkHash` instead.

7. **Emit `existingCredentials`.** In the **same signed `algPolicy`
   map in `authData.extensions`** (key `1`, alongside the `bindings` of
   step 6 at key `2`), the authenticator publishes the credential IDs it
   currently holds for `(rpId, user.id)`, including the credential
   used for the assertion and any credential just added in step 5.
   It is carried in the signed `authData` — not in
   `unsignedExtensionOutputs` — precisely because the RP acts on it
   destructively (see below). The RP uses this list to detect and sweep
   ORPHAN credentials — credentials that exist on the authenticator but
   that the RP does not have registered (typically because a prior
   `createdCredentials` upload failed). See "Orphan credentials and
   convergence" in §3 for the full RP-side handling. Authenticators that
   do not support the relaxed credential model (§1) MUST still emit
   `existingCredentials`, containing the single credential ID used
   for the assertion.

The satisfaction rule is intentionally **best-supported**, not
**any-in-group**. The difference matters when an authenticator's algorithm
capability changes over its lifetime:

* If an authenticator can mint ML-DSA-87 but only has an ML-DSA-65
  credential for the account, the group `[ML-DSA-87, ML-DSA-65, ML-DSA-44]`
  is *unsatisfied* — `B` is ML-DSA-87 and no credential for it exists.
  The authenticator mints ML-DSA-87 on the next ceremony.
* After a firmware update that adds ML-DSA-87 support, `B` advances from
  ML-DSA-65 to ML-DSA-87 and the upgrade happens automatically. The RP
  does not need to know that the authenticator was upgraded.
* An authenticator that never gains ML-DSA-87 support has `B` permanently
  at ML-DSA-65; once a -65 credential exists the group stays satisfied
  forever. No retry loop, no thrashing.

Convergence is per-group, per-authenticator, and bounded by the
authenticator's capability set. "Best I support" is a property of the
authenticator, not state, so the rule does not require any new
remembered flags.

There is intentionally **no per-ceremony numeric cap** on how many
groups an authenticator may fill *in a single tap*. A high-end platform
authenticator may fill three groups at once; a constrained roaming
security key may fill one group per ceremony and spread the rest across
future sign-ins. The spec leaves this to authenticator discretion; the
convergence guarantee is per-group, not per-ceremony.

**How many groups?** There **is**, however, a hard cap on the *total
number of groups* an RP may list in `createAlgs`: **at most 3**. This is
a structural limit, not a tuning knob, and the client **MUST** reject a
`get()` whose `createAlgs` has more than three groups with a `TypeError`.
The cap exists because every group an authenticator can satisfy becomes a
*persistent credential slot* consumed on that authenticator for this
account, and roaming security keys hold only ~25–50 slots total. An RP
that lists five or six groups would silently multiply its per-account
storage footprint on exactly the most constrained devices — the failure
mode this proposal is trying to avoid. Three groups is the ceiling of
every legitimate configuration:

* **One group** — a single PQC credential (or a self-fallback composite).
  The common steady state.
* **Two groups** — PQC plus a classical fallback. The canonical
  crypto-agility / emergency-downgrade configuration.
* **Three groups** — a transient migration peak: a newly-standardized PQC
  family, the current PQC family, and the classical fallback held in
  parallel while the RP evaluates the new family (see Worked Example C).
  Once the RP commits, it migrates away from one family and drops back to
  two.

Anything beyond three means asking every authenticator to carry four or
more credentials per account — a storage anti-pattern rather than a real
agility requirement. An RP evaluating two new families at once should
*sequence* them, not hold both plus the incumbent plus classical at once.
Note the cap is on the **number of groups** (the outer list) only — the
length of each individual group is unbounded, because a group of any
length still mints **exactly one** credential (its best-supported entry).
Adding more preference fallbacks *within* a group costs nothing; adding
another group costs a slot.

**Why groups, not a flat list?** The natural alternative is a single
flat preference list with "mint the one best-supported algorithm"
semantics — e.g. `createAlgs: [ML-DSA-87, ML-DSA-65, ML-DSA-44, ES256, RS256]`
→ mint only the single strongest entry the authenticator supports.
Groups are a strict **generalization** of that flat list: the flat
"mint one best" behavior is exactly the **single-group** case
`createAlgs: [[ML-DSA-87, ML-DSA-65, ML-DSA-44, ES256, RS256]]`. So
adopting groups loses nothing the flat list offers, while gaining the
one thing the flat list structurally cannot provide.

That missing thing is **pre-provisioning a fallback in a second
algorithm**. A flat "mint one" list mints exactly one credential. If
that credential is a PQC credential — which it will be, because PQC
sits at the front of the preference order — then no classical
credential is ever minted, and the server-registered classical
fallback that the entire emergency-downgrade story depends on never
comes into existence. This "PQC created first ⇒ classical never
created" failure is intrinsic to the flat shape, not a tuning problem:
reordering the list to put classical first merely inverts which
algorithm is stranded.

Groups fix this by construction: each group converges independently to
its own best-supported credential, so `[[ML-DSA...], [ES256, RS256]]`
mints **one PQC credential and one classical credential**. Each group
still expresses "give me the strongest one you can mint from this
group" — the property the flat list had — but the RP can now ask for
that across several independent buckets at once:

* *PQC variants (one group):* `[ML-DSA-87, ML-DSA-65, ML-DSA-44]` — any
  ML-DSA variant, preferring -87, one per authenticator (not all three).
* *Classical fallback (a second group):* `[ES256, RS256]` — ECC
  preferred, RSA accepted from authenticators that don't support ECC.

This also accommodates a genuine **difference of opinion across RPs**
about how PQC-plus-classical hedging should be expressed. There are two
defensible philosophies, and organizations legitimately disagree on
which is better:

* **One composite credential.** Treat a composite ML-DSA+classical
  algorithm (e.g. `ML-DSA-65-ECDSA-P384-SHA512`) as a *single*
  algorithm and mint *one* credential whose signature carries both legs.
  RPs who prefer a single credential per account — simpler database
  model, one registration record, hedging handled inside the
  algorithm — favor this. However this only works when every authenticator
  support composite credentials.
* **Two separate credentials.** Mint a *pure* ML-DSA credential and a
  *separate* classical credential, hedging at the credential layer
  rather than inside one algorithm. RPs who want each leg
  independently registrable, revocable, and observable — or who do not
  want to depend on a composite algorithm being standardized and widely
  supported — favor this.

The group model is deliberately **neutral** between the two. An RP that
prefers the separate-credentials philosophy expresses it as two groups
(`[[ML-DSA...], [ES256, RS256]]`) and gets two independent credentials.
An RP that prefers the composite philosophy simply lists the composite
algorithm — in a single group, even alongside a pure-PQC fallback for
authenticators that lack composite support
(`[[ML-DSA-65-ECDSA-P384-SHA512, ML-DSA-65]]`) — and gets one credential.
Nothing in this proposal forces either choice: groups *add* the
separate-credentials option for the RPs who want it without taking the
composite option away from the RPs who prefer that.

Groups make "one (best) credential per group" the explicit, structural
contract, and let each RP choose how many buckets it wants — one group
for a single-credential strategy, several for explicit fallback and
multi-family evaluation (see "Recommended configuration for RPs"
and Worked Example C).

#### CTAP mapping

The two WebAuthn-layer inputs map onto `authenticatorGetAssertion`
along the **same layering** they have in the API — core credential
selection stays at the top level, and only the silent-mint machinery
lives in the extension:

* **`acceptedAlgs` → a top-level `authenticatorGetAssertion`
  parameter**, *not* an `algPolicy` extension field. It governs which
  discoverable credentials are eligible and their signing-preference
  order — authenticator-core selection behavior that must work for a
  plain assertion with no minting at all. Burying it in the extension
  would wrongly make algorithm filtering conditional on the silent-mint
  feature being present. (This is the CTAP edit noted in Open Question
  2.)
* **`algPolicy` extension carries only `createAlgs` and
  `createExtensions`** — the inputs that exist solely to drive
  in-ceremony minting.
* **PRF salts nest inside `createExtensions`.** Because the client
  performs the PRF → `hmac-secret` translation, by the CTAP layer the
  `prf` member of `createExtensions` has become **`hmac-secret-mc`**
  (CTAP 2.2) carried *inside* `algPolicy.createExtensions`, where it
  binds to the mint. It **MUST NOT** be hoisted to the top-level
  extensions map: the top-level `hmac-secret` slot evaluates against the
  **asserting** credential, so the two PRF evaluations are kept
  unambiguous — top-level `hmac-secret` → old credential,
  `algPolicy.createExtensions["hmac-secret-mc"]` → minted credential.

Symmetrically on the response: the asserting credential's outputs
(including its `hmac-secret` PRF output) sit in the signed
`authData.extensions`, while each minted credential's attestation object
— and the minted credential's own `hmac-secret` PRF output nested in
*its* `authData.extensions` — travels in `unsignedExtensionOutputs`
under `algPolicy`, authenticated by the signed `pkHash` binding (see §2
steps 6–7).

### 3. RP-side handling

Throughout the code samples below, algorithms are referred to by their
canonical names (`ML-DSA-87`, `ML-DSA-65`, `ES256`, `RS256`, etc.) via a
placeholder `alg` lookup object (e.g. `alg["ML-DSA-65"]`). The normative
numeric COSE codepoints live in the IANA
[COSE Algorithms registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).

```js
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge,
    rpId: "example.com",
    userVerification: "preferred",
    // Top-level: RP currently accepts any ML-DSA variant (preferring
    // -87), and ECC, and RSA — in that preference order at assertion
    // time. Symmetric counterpart of `pubKeyCredParams` on create().
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
        // RP wants every account to hold one PQC credential and one
        // classical fallback. Each group is ordered strongest-first; the
        // authenticator reaches for the best entry it supports.
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
        // Extension inputs applied to every silently-minted credential.
        // Same shape as `extensions` on create(). Use this to enable
        // any create-time per-credential state the RP needs on the new
        // credentials (PRF, largeBlob, credBlob, ...).
        createExtensions: {
          // e.g. prf: {} ...
        },
      },
    },
  },
});

const ext = assertion.getClientExtensionResults().algPolicy;

// Register any new credentials the authenticator just minted in this
// ceremony, after verifying the asserter-binding for each one (see §2
// step 6). `registerAdditionalCredential` parses the `algPolicy`
// authenticator-extension output carried in
// `assertion.response.authenticatorData`, locates the binding entry
// whose `id` matches `created.id`, and refuses to persist `created`
// unless the binding's `pkHash` matches SHA-256 of the canonical CBOR
// encoding of the new credential's COSE public key and the binding's
// `alg` matches its algorithm. Existing credentials are left untouched.
for (const created of ext?.createdCredentials ?? []) {
  await rp.registerAdditionalCredential(account, assertion, created);
}

// Orphan sweep: any credential ID the authenticator holds for this
// account but that the RP does not recognize is an orphan — typically
// from a prior `createdCredentials` upload that failed. Asking the
// provider to delete it re-opens the corresponding `createAlgs` group
// for a fresh mint on the next ceremony.
//
// The ID list MUST be read from the SIGNED authData, never from
// getClientExtensionResults(): the RP acts on it destructively
// (signalUnknownCredential = deletion), so it must come from a signed
// source. `existingCredentialsFromAuthData` parses key 1 of the
// `algPolicy` map in `assertion.response.authenticatorData`.
const existingIds = rp.existingCredentialsFromAuthData(assertion);
const knownIds = new Set(await rp.getCredentialIds(account));
for (const id of existingIds) {
  if (id === assertion.id) continue;       // never sweep the credential we just used
  if (knownIds.has(id)) continue;          // RP already has this one
  await PublicKeyCredential.signalUnknownCredential({
    rpId: "example.com",
    credentialId: id,
  });
}
```

The RP-side state machine for a typical forward migration is:

* **Phase 0 — single algorithm.** RP omits both `acceptedAlgs` and the
  `algPolicy` extension; behaves as today.
* **Phase 1 — dual-accept, dual-provision (standing state).** RP sets
  `acceptedAlgs: [PQC, legacy]` and
  `createAlgs: [[PQC variants...], [legacy variants...]]`. This is
  the RP's standing state for an extended period (months to years),
  not a transient phase. Both groups keep doing useful work
  indefinitely:
  - The PQC group mints PQC credentials for stragglers, for new
    users who happened to register classical-only via `create()`,
    and (via the best-supported rule) re-converges to a stronger
    variant after authenticator firmware upgrades.
  - The legacy group mints a fallback credential for new users
    registered PQC-only via `create()`, maintaining the
    server-registered fallback coverage that makes emergency
    downgrade safe (see "Emergency downgrade depends on
    server-confirmed fallback coverage" below).
* **Phase 2 — dual-accept, PQC-only provisioning.** The RP has
  concluded that the PQC algorithm is stable and no longer wants to
  manufacture *new* classical fallbacks, but it **cannot** yet drop
  classical from `acceptedAlgs` because a residual population of
  users/authenticators still has no PQC credential. So it keeps
  acceptance wide but narrows provisioning to PQC only:
  `acceptedAlgs: [PQC, legacy]` (unchanged from Phase 1) while
  `createAlgs: [[PQC variants...]]` (the legacy group is dropped). The
  effect on each population:
  - **PQC-capable authenticators** that still assert with a legacy
    credential get a PQC credential silently minted in-ceremony (the
    PQC group is unsatisfied), exactly as in Phase 1 — the conversion
    happens with no user friction.
  - **Authenticators that cannot silently mint PQC** (they do not
    support the relaxed credential model of §1, or support no algorithm
    in the PQC group) produce a legacy assertion with an empty
    `createdCredentials`. Because the RP wants these users converted,
    it should detect "asserted with a legacy credential **and** no PQC
    credential was minted or already on file" and **guide the user
    through an explicit `navigator.credentials.create()` for a PQC
    credential** (possibly on a different or upgraded authenticator).
    This is the one phase where the RP actively nudges, rather than
    relying solely on silent backfill. The "no PQC credential on file"
    test **MUST** be evaluated against the RP's own database, not just
    this ceremony's `createdCredentials` — otherwise a user whose PQC
    credential lives on a *different* authenticator is prompted on every
    legacy device they own. The RP should also suppress the prompt to at
    most once per device/session (e.g. a per-user, per-authenticator
    "already nudged" marker), so a user who declines or defers is not
    nagged on every sign-in.
  - **New users registering PQC-only via `create()`** no longer receive
    a classical fallback (the legacy group is gone) — which is
    deliberate: the RP has decided new accounts do not need one.
  Phase 2 is the bridge that *drains* the classical population down to
  zero PQC-less accounts before the RP is willing to stop accepting
  classical at all. The RP stays in Phase 2 until its database shows the
  PQC-less population has fallen below whatever threshold it considers
  safe for the Phase 3 cutover.

  Note the tradeoff Phase 2 accepts: by dropping the legacy group from
  `createAlgs`, the RP stops manufacturing the **server-registered
  classical fallbacks** that make emergency downgrade safe (see
  "Emergency downgrade depends on server-confirmed fallback coverage"
  below). Existing fallbacks are retained, but new accounts created in
  Phase 2 will not have one. This is deliberate — it is the point at
  which the RP judges PQC trustworthy enough that fresh downgrade
  insurance is no longer worth the extra credential slot — but the RP
  should enter Phase 2 consciously, knowing classical-fallback coverage
  for new users stops growing from here.
* **Phase 3 — PQC only.** RP ships the final cutover. Coming from
  Phase 2, `createAlgs` is already PQC-only, so the only change is
  dropping the legacy algorithms from `acceptedAlgs` (now
  `acceptedAlgs: [PQC]`). (An RP that skipped Phase 2 makes both edits
  at once — drop the legacy group from `createAlgs` *and* the legacy
  algorithms from `acceptedAlgs`.) Users
  asserting with a legacy credential get filtered out at step 1; the
  platform's discoverable-credential picker will not offer the legacy
  credential. The dormant legacy credential lingers on the authenticator
  but is inert — the RP will not validate an assertion produced by it.
  If the RP wants to reclaim authenticator storage, it issues a
  [Signal API](signal-api.md) `signalAllAcceptedCredentials` per user
  listing only the PQC credential ID; the credential provider deletes
  any other credential under `(rpId, user.id)` that isn't on the list.
  This is reliable on synced / platform credential providers and
  best-effort on roaming authenticators — but unlike a deletion that
  runs in-ceremony, a failed or never-delivered cleanup signal cannot
  lock the user out, because nothing they could authenticate with has
  been removed from `acceptedAlgs`.

**Emergency downgrade** is the same state machine run sideways. If a
weakness is announced in the currently preferred algorithm, the RP
changes `acceptedAlgs` to put the fallback first (or to exclude the
weakened algorithm entirely). Users with a **server-registered**
fallback credential sign in seamlessly; users without one are funneled
into re-enrollment. The RP knows ex ante which users are in which
bucket by querying its own database — see "Emergency downgrade depends
on server-confirmed fallback coverage" below for the discipline.

#### Operational guidance for RPs

The best-supported satisfaction rule lets the RP write `createAlgs` once
and leave it alone across authenticator firmware upgrades, security key
turnover, and OS updates that add new algorithm support. A small set of
rules captures the operational discipline:

1. **Order each group in true RP preference, strongest first.** The
   authenticator always reaches for the earliest entry it supports, so
   the order is load-bearing. `[ML-DSA-87, ML-DSA-65, ML-DSA-44]` — not
   `[ML-DSA-65, ML-DSA-87, ML-DSA-44]`.
2. **Ship `createAlgs` once. Do not reshape it just because authenticator
   capabilities are evolving.** A stable policy already converges each
   authenticator to the strongest entry it can mint, today and after
   every firmware update. There is no need to chase the population.
3. **Reshape `createAlgs` only when *RP* policy changes** — e.g. adding
   a new group for a newly-standardized algorithm class, dropping a group
   after an emergency downgrade.
4. **Cleanup is optional and out of band.** This extension never
   deletes credentials. Old credentials filtered out by `acceptedAlgs`
   sit dormant on the authenticator; they will never be selected at
   assertion time because the RP won't validate them. If you want to
   reclaim that storage — e.g. after a Phase 3 PQC-only cutover — use
   the [Signal API](signal-api.md). `signalAllAcceptedCredentials`
   (snapshot, per user) is the right shape for cutover cleanup;
   `signalUnknownCredential` (per credential ID) is the right shape
   for revoking a specific compromised credential. Signal API delivery
   is reliable on synced / platform credential providers and
   best-effort on roaming authenticators — but because the extension
   never removes the only credential a user could authenticate with,
   a failed cleanup signal is a hygiene miss, not a lockout. Doing
   nothing at all is also fine: dormant credentials are inert.
5. **Reconcile state on every ceremony.** Sweep orphans surfaced by
   the signed `existingCredentials` list in `authData` (issue
   `signalUnknownCredential` for any ID not in your database), and
   measure server-side fallback coverage before invoking emergency
   downgrade. See "Orphan credentials and convergence" and "Emergency
   downgrade depends on server-confirmed fallback coverage" below.

#### PRF and `hmac-secret` on silently-minted credentials

If the RP relies on the [PRF extension](prf-extension.md) — e.g. to
derive an end-to-end-encryption key from the credential — silent mint
needs care, because **PRF output is per credential**. Each credential
has its own authenticator-held PRF secret (on security keys, the
`hmac-secret` `CredRandom` values, generated at credential creation and
never exported). The same PRF input therefore yields a **different**
output under the silently-minted credential than under the credential
the user just asserted with. Migration is *not* transparent for
PRF-derived secrets: data wrapped under the old credential's PRF output
cannot be unwrapped with the new credential's output.

This is the reason `createExtensions` exists and the reason its PRF
input must be evaluated **at mint time**: the mint is the one moment the
RP can obtain the new credential's PRF output in the same ceremony where
the user is still proving control of the old credential, so it can
re-wrap old → new without a second round trip.

The mechanics differ by transport, matching how PRF maps onto each:

* **Roaming security keys (USB/NFC/BLE).** Classic `hmac-secret`
  evaluates **only at assertion**; at `makeCredential` it merely
  provisions the secret and returns no output. A silent mint is a
  `makeCredential` nested inside a `getAssertion`, so getting the new
  credential's PRF output in-ceremony requires **`hmac-secret-mc`**
  (CTAP 2.2), which accepts `hmac-secret` salts at `makeCredential` and
  returns the evaluated output in the MC response. The PRF inputs are
  hashed to salts, encrypted under the **same** PIN/UV-protocol shared
  secret already established for the assertion (one key agreement,
  reused), evaluated against the new credential's freshly-generated
  `CredRandom`, and returned encrypted under that shared secret.
* **Hybrid (caBLE) and platform authenticators.** The transport already
  provides confidentiality, so PRF evaluations are conveyed directly
  rather than as encrypted `hmac-secret` salts. Platform authenticators
  already evaluate PRF at `create()` time, so the new credential's PRF
  output is returned inline with the mint. This is the
  straightforward path.

Because the mint reuses the assertion's single UV gesture (§2 step 4),
the new credential's PRF output is drawn from the same UV regime
(`CredRandomWithUV` when UV was performed, otherwise the without-UV
secret) as the assertion's own PRF output — the RP is not accidentally
comparing a with-UV value against a without-UV one.

**Graceful degradation.** If a roaming authenticator supports
`hmac-secret` but **not** `hmac-secret-mc`, the mint still produces a
PRF-capable credential, but the extension output reports
`prf: { enabled: true }` with **no `results`**. The RP cannot obtain the
new credential's PRF output until a subsequent assertion against that
credential. The RP **MUST NOT** block the migration on synchronously
obtaining the PRF output; it should treat the output as deferred,
exactly as it treats `createdCredentials` coverage as opportunistic,
and complete any PRF re-wrap on the first ceremony that does surface the
output.


### 4. Selection and pruning on the authenticator / OS

**Selection.** When an authenticator or OS holds multiple credentials for
the same `(rpId, user.id)`:

* The user-visible representation in account choosers is a single account.
  The algorithm of the underlying credential is not surfaced.
* For an assertion with `acceptedAlgs`, the credential with the
  earliest matching algorithm is used automatically.
* For an assertion without `acceptedAlgs`, the authenticator picks one
  credential. Implementations SHOULD prefer the most recently created /
  most recently used credential so that an RP that has not yet adopted
  `acceptedAlgs` still gets the strongest available credential.

**Pruning.** The `algPolicy` extension never deletes credentials. Under
group-semantics `createAlgs` a non-preferred credential is *standing
insurance*, not legacy state to be cleaned up; and a credential filtered
out by `acceptedAlgs` is inert (the RP will not validate an assertion
produced by it). The pruning rules below pin this down:

* An authenticator / OS **MUST NOT** autonomously prune a credential
  merely because its algorithm has fallen out of `acceptedAlgs` on a given
  ceremony. The RP's accept-list can change in either direction; today's
  unused fallback may be tomorrow's only working credential.
* An authenticator / OS **MUST NOT** autonomously prune a credential
  merely because a credential with a more recent or more preferred
  algorithm now exists for the same `(rpId, user.id)` — including a
  credential that occupies an earlier position in the same `createAlgs`
  group. Intra-group upgrades are RP-driven, not
  authenticator-autonomous.
* An authenticator / OS **MAY** prune a credential when explicitly
  authorized by the RP via the [Signal API](signal-api.md):
  `signalAllAcceptedCredentials` (snapshot, per user) instructs the
  provider to remove any credential under `(rpId, user.id)` not on the
  list; `signalUnknownCredential` (per credential ID) instructs the
  provider to remove a specific credential. Pruning under Signal API
  authorization remains at provider discretion (the provider MAY hide
  rather than delete, MAY require user confirmation, etc.), as
  documented in the Signal API explainer.

The net effect: the RP, not the authenticator, decides when a credential
is retired. Authenticators only ever *add* to the credential set
autonomously; they only *remove* when the RP signals it post-ceremony.
Because the `algPolicy` extension itself never removes credentials, no
combination of `acceptedAlgs` and `createAlgs` can strand a user — the
worst case is a dormant credential lingering on a roaming authenticator
that never received a Signal API cleanup, which is harmless storage
overhead.

### 5. Authenticator capability and fallback

* Authenticators that **do not** support the relaxed `(rpId, user.id, alg)`
  model treat the silent-create step as if every group were over-budget:
  they perform the assertion normally and return an empty (or absent)
  `createdCredentials`. The RP-side migration simply proceeds more slowly for
  users on those authenticators (or not at all).
* Authenticators that **do** support the relaxed model but cannot afford
  to fill every unsatisfied group in one ceremony fill any subset
  (preferring earlier groups) and let subsequent ceremonies cover the
  rest. The RP must not assume single-ceremony coverage.
* Authenticators that **do not** support any algorithm in `acceptedAlgs` are
  not surfaced as candidates and the user is shown the standard "no
  credential available" UI.
* Authenticators that support no algorithm in a given unsatisfied group
  simply leave that group unfilled. The group stays unsatisfied indefinitely
  on that authenticator, which is the correct outcome: the RP's standing
  policy is unsatisfiable on that hardware.
* Clients that do not understand the top-level `acceptedAlgs` member
  ignore it (per the standard IDL rules for unknown dictionary
  members); the candidate set is not filtered by algorithm and the
  RP's server-side `alg` check catches anything outside policy.
  Clients that do not understand the `algPolicy` extension drop it
  (per the standard WebAuthn extension processing rules) and the
  assertion proceeds as a normal assertion. The two features degrade
  independently: a client that supports `acceptedAlgs` but not
  `algPolicy` still delivers the candidate-set filter, which is
  useful on its own; a client that supports both delivers the full
  migration loop.

## Recommended configuration for RPs

Before writing any configuration, an RP should pick a **crypto
strategy**. The group model deliberately supports two, because
different RPs want different things and the API should not force a
choice between them. Both are expressed as `createAlgs` configurations
that differ only in the number of groups, and the choice is a matter of
RP preference rather than capability:

* **Explicit fallback (pure PQC + classical) — two groups.** Hedge at
  the *credential* layer: hold a pure-PQC credential plus a separate
  classical credential.
* **Composite / hybrid (single credential) — one group.** Hedge inside
  the *algorithm*: hold one credential whose signature carries both a
  PQC and a classical leg.

The two strategies, each with its recommended configuration, follow.

### Strategy 1 — Explicit fallback (pure PQC + classical)

For the migration scenario this explainer is designed for —
classical algorithms in production today, PQC algorithms arriving —
this **dual-credential standing-state** configuration is the
recommended default for RPs who hedge at the credential layer. Every
PQC-capable authenticator ends up holding both a PQC credential
(preferred at assertion time) and a classical fallback credential
(server-registered, so emergency downgrade actually works) for every
account.

```js
// On navigator.credentials.create() for new registrations:
pubKeyCredParams: [
  { type: "public-key", alg: alg["ML-DSA-87"] },
  { type: "public-key", alg: alg["ML-DSA-65"] },
  { type: "public-key", alg: alg["ML-DSA-44"] },
  { type: "public-key", alg: alg["ES384"] },
  { type: "public-key", alg: alg["ES256"] },
  { type: "public-key", alg: alg["RS256"] }
]

// On navigator.credentials.get() for sign-in:
//   top-level (mirrors pubKeyCredParams above):
acceptedAlgs: [
  alg["ML-DSA-87"],
  alg["ML-DSA-65"],
  alg["ML-DSA-44"],
  alg["ES384"],
  alg["ES256"],
  alg["RS256"]
]
//   inside extensions.algPolicy:
algPolicy: {
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
    ]
  ]
}
```


"PQC-capable authenticator" means the authenticator supports at
least one entry in the PQC group. Every user has a
server-registered classical credential to fall back on under
emergency downgrade. If either leg is later broken, the other is
already pre-provisioned and server-registered, so the downgrade is a
configuration change rather than a recovery event.

The cost is modest:

- Two credentials per account on the authenticator: negligible for
  synced / platform credential providers; bounded but real on
  roaming security keys with small (~25–50 slot) storage.
- One extra public key per account on the server.


### Strategy 2 — Composite / hybrid (single credential)

If/when **composite signature algorithms** are standardized and widely
supported — a single COSE algorithm identifier representing both a
PQC and a classical signature in one credential, e.g.
`ML-DSA-65-ECDSA-P256-SHA512` — an RP that prefers to hedge inside the
algorithm uses a single group listing the composite variants. This
explainer uses the following composite names for concreteness; note
that none of them has an officially assigned COSE algorithm identifier
yet, so the numeric code points are still to be determined:

* `ML-DSA-87-ECDSA-P384-SHA512`
* `ML-DSA-65-ECDSA-P384-SHA512`
* `ML-DSA-65-ECDSA-P256-SHA512`
* `ML-DSA-44-ECDSA-P256-SHA256`

NOTE: COSE public key format and signature format also needs to be defined
for above algorithms. COSE public key present in authData is a single
CBOR map with individual fields and not a concatenation of individual
COSE public keys for the algorithms involved. How these will be defined
is unknown at this point. Similarly signature fields in WebAuthn/CTAP
is a binary blob and not a concatenation of individual algorithms signature.
Hence these details are unknown at this point and needs to be figured
out before platforms can commit to these algorithms implementation and
RP can commit to this configuration.

Another point to consider here is whether the authenticator fleet is
homogeneous or not for the RP.

#### Strategy 2 - Homogeneous Fleet Configuration

The possible recommended configuration for this strategy for a homogeneous is a single group:

```js
// On navigator.credentials.create() for new registrations:
pubKeyCredParams: [
  { type: "public-key", alg: alg["ML-DSA-87-ECDSA-P384-SHA512"] },
  { type: "public-key", alg: alg["ML-DSA-65-ECDSA-P384-SHA512"] },
  { type: "public-key", alg: alg["ML-DSA-65-ECDSA-P256-SHA512"] },
  { type: "public-key", alg: alg["ML-DSA-44-ECDSA-P256-SHA256"] }
]

// On navigator.credentials.get() for sign-in:
//   top-level (mirrors pubKeyCredParams above):
acceptedAlgs: [
  alg["ML-DSA-87-ECDSA-P384-SHA512"],
  alg["ML-DSA-65-ECDSA-P384-SHA512"],
  alg["ML-DSA-65-ECDSA-P256-SHA512"],
  alg["ML-DSA-44-ECDSA-P256-SHA256"]
]
//   inside extensions.algPolicy:
algPolicy: {
  createAlgs: [
    [
      alg["ML-DSA-87-ECDSA-P384-SHA512"],
      alg["ML-DSA-65-ECDSA-P384-SHA512"],
      alg["ML-DSA-65-ECDSA-P256-SHA512"],
      alg["ML-DSA-44-ECDSA-P256-SHA256"]
    ]
  ],
}
```

Here the fallback question collapses: a single composite credential
is its own emergency-downgrade target, because a break in one leg
still leaves the other leg of the same credential intact. No second
group is needed.

#### Strategy 2 - Heterogeneous Fleet Configuration

On a **heterogeneous fleet** where some authenticators cannot mint a
composite, and RP also want to support classical authenticators
above homogeneous configuration doesn't work.
To solve that, RP have to list the pure-PQC variant and classical algorithms
as a fallback similar to strategy 1. However, in this configuration,
for authenticators who support composite algorithm, RP will get a composite
algorithm.

```js
// On navigator.credentials.create() for new registrations:
pubKeyCredParams: [
  { type: "public-key", alg: alg["ML-DSA-87-ECDSA-P384-SHA512"] },
  { type: "public-key", alg: alg["ML-DSA-65-ECDSA-P384-SHA512"] },
  { type: "public-key", alg: alg["ML-DSA-65-ECDSA-P256-SHA512"] },
  { type: "public-key", alg: alg["ML-DSA-44-ECDSA-P256-SHA256"] },
  { type: "public-key", alg: alg["ML-DSA-87"] },
  { type: "public-key", alg: alg["ML-DSA-65"] },
  { type: "public-key", alg: alg["ML-DSA-44"] },
  { type: "public-key", alg: alg["ES384"] },
  { type: "public-key", alg: alg["ES256"] },
  { type: "public-key", alg: alg["RS256"] }
]

// On navigator.credentials.get() for sign-in:
acceptedAlgs: [
  alg["ML-DSA-87-ECDSA-P384-SHA512"],
  alg["ML-DSA-65-ECDSA-P384-SHA512"],
  alg["ML-DSA-65-ECDSA-P256-SHA512"],
  alg["ML-DSA-44-ECDSA-P256-SHA256"],
  alg["ML-DSA-87"],
  alg["ML-DSA-65"],
  alg["ML-DSA-44"],
  alg["ES384"],
  alg["ES256"],
  alg["RS256"]
]
//   inside extensions.algPolicy:
algPolicy: {
  createAlgs: [
    [
      alg["ML-DSA-87-ECDSA-P384-SHA512"],
      alg["ML-DSA-65-ECDSA-P384-SHA512"],
      alg["ML-DSA-65-ECDSA-P256-SHA512"],
      alg["ML-DSA-44-ECDSA-P256-SHA256"],
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
}
```

## Worked examples

### Worked example A: forward migration (ECDSA → ML-DSA)

1. **Today.** Alice has an ES256 passkey for `example.com` on her phone.
   `example.com` calls `get()` with no extension; the ES256 credential is
   used.
2. **Phase 1 deployment.** `example.com` updates its frontend to send:
   * `acceptedAlgs: [ML-DSA-87, ML-DSA-65, ML-DSA-44, ES256, RS256]`
   * `createAlgs: [[ML-DSA-87, ML-DSA-65, ML-DSA-44], [ES256, RS256]]`

   Each group is ordered strongest-first per the operational guidance.
   The first group says "the strongest ML-DSA variant this authenticator
   supports"; the second says "ECC, or RSA if ECC is not supported." The
   RP wants every account to hold one credential from each group, with
   ML-DSA preferred at assertion time.
3. **Next sign-in (PQC-capable phone, supports only ML-DSA-65).** The
   authenticator asserts with the existing ES256 credential. It then
   evaluates `createAlgs` group by group: the ECC/RSA group is satisfied
   (ES256 present and ES256 is best-supported). The ML-DSA group's
   best-supported entry is ML-DSA-65 (no -87 support yet); no -65
   credential exists, so the group is unsatisfied. The authenticator
   silently generates a new ML-DSA-65 credential for the same account,
   includes it in `createdCredentials`, and emits
   `existingCredentials: [ES256 id, ML-DSA-65 id]`. `example.com`
   registers the ML-DSA-65 public key against Alice's account; both
   IDs are now in its database, so the orphan-sweep loop has nothing
   to do. The ES256 public key remains valid.
4. **Sign-in after.** Both credentials exist; the authenticator picks
   the ML-DSA-65 credential because it appears first in `acceptedAlgs`
   that is supported. The ES256 credential is not used but is retained.
   Best-supported in each group has an existing credential, so both
   groups are satisfied and no new credentials are minted.
5. **Later: Alice's phone receives a firmware update adding ML-DSA-87.**
   On her next sign-in, best-supported in the PQC group is now ML-DSA-87;
   no -87 credential exists, so the group becomes unsatisfied. The
   authenticator silently mints an ML-DSA-87 credential. `example.com`
   registers it. No RP-side change was needed.
6. **Phase 3 cutover.** `example.com` ships
   * `acceptedAlgs: [ML-DSA-87, ML-DSA-65, ML-DSA-44]`
   * `createAlgs: [[ML-DSA-87, ML-DSA-65, ML-DSA-44]]` (legacy group dropped)

   On Alice's next sign-in the platform offers only the ML-DSA
   credentials, preferring -87. She signs in with -87; her ES256
   credential is filtered out of the candidate set and is never
   selected. It sits dormant on the authenticator — inert, because the
   RP will not validate an assertion produced by it. If `example.com`
   wants to reclaim the storage, it issues
   `signalAllAcceptedCredentials` for Alice listing only her PQC
   credential ID; her phone (a synced credential provider) honors the
   signal reliably. If Alice had been using a roaming security key,
   the cleanup signal would be best-effort, but the dormant ES256
   credential is harmless either way. If `example.com` instead wants
   to keep the ES256 credential as cold downgrade insurance, it does
   nothing — the dormant credential remains available the moment the
   RP widens `acceptedAlgs` to include ES256 again.
7. **Sign-in on a non-PQC-capable security key.** During Phase 1 no
   entry in the PQC group is supported, so the group is unsatisfiable and
   skipped; `createdCredentials` contains nothing new (the ECC/RSA group
   was already satisfied by the existing credential). During Phase 3 it
   has no algorithm in `acceptedAlgs` it can satisfy, and `example.com`
   must surface a "please enroll a new authenticator" flow for that user
   through some other channel.

### Worked example B: emergency downgrade

This example assumes `example.com` ran the Phase 1 policy from Example A
for long enough that most users have a **server-registered** ES256
credential alongside their ML-DSA-65 credential.

1. **Tuesday morning.** A practical attack against ML-DSA-65 is published.
2. **Tuesday afternoon.** `example.com` ships a configuration change:
  ```js
  acceptedAlgs: [
    alg["ES256"],
    alg["RS256"]
  ]
  createAlgs: [
    [
      alg["ES256"],
      alg["RS256"]
    ]
  ]
  ```

   The ML-DSA group is dropped from `createAlgs` entirely (the RP no longer
   wants new ML-DSA credentials), and ML-DSA is no longer accepted at
   assertion time. The classical-fallback group remains — a no-op for
   most users but covers any new PQC-only accounts created recently.
3. **Alice signs in (had both credentials).** The candidate set filters
   down to the ES256 credential. She signs in with no friction. The
   surviving `createAlgs` group finds an ES256 credential already present,
   so no new credential is minted. `example.com` follows up with
   `signalUnknownCredential` naming the ML-DSA-65 credential ID, and
   Alice's phone (at its discretion) drops the now-revoked credential.


### Worked example C: a new PQC family arrives (multi-family evaluation and migration)

This example shows two things the group model makes possible that a
flat "mint one" list cannot: holding **three algorithm families at
once** to evaluate them, and migrating from ML-DSA to a newer PQC
family that may or may not have a composite variant.

Suppose that some years after Example A has stabilized, a new PQC
signature family — call it **NewPQC** (variants `NewPQC-A`, `NewPQC-B`)
— is standardized, and `example.com` wants to evaluate it against
ML-DSA for signing latency, credential size, and authenticator support
before committing.

* **Evaluation phase — three families in parallel.** `example.com`
  ships a three-group policy:

  ```js
  acceptedAlgs: [
    alg["NewPQC-A"],
    alg["NewPQC-B"],
    alg["ML-DSA-87"],
    alg["ML-DSA-65"],
    alg["ML-DSA-44"],
    alg["ES384"],
    alg["ES256"],
    alg["RS256"]
  ]
  createAlgs: [
    [
      alg["NewPQC-A"],
      alg["NewPQC-B"]
    ],
    [
      alg["ML-DSA-87"],
      alg["ML-DSA-65"],
      alg["ML-DSA-44"]
    ],
    [
      alg["ES384"],
      alg["ES256"],
      alg["RS256"]
    ]
  ]

  ```

  Over a few sign-ins, every authenticator converges to **one
  credential per family it supports**: a NewPQC credential (if capable),
  an ML-DSA credential, and a classical fallback. `example.com` now
  measures, per family, real-world signing latency and what fraction of
  its fleet can mint each — using data it can only gather because all
  three credentials coexist on the same accounts. A flat "mint one"
  list could not do this: it would mint only the single front-of-list
  algorithm, leaving the RP nothing to compare.

* **Selection follows `acceptedAlgs`.** With NewPQC at the front of
  `acceptedAlgs`, NewPQC-capable authenticators assert with NewPQC while
  still carrying ML-DSA and classical credentials as standing insurance.
  The RP can reorder `acceptedAlgs` (e.g. put ML-DSA first) to A/B the
  assertion path without minting or deleting anything.

* **Commit and migrate away from ML-DSA.** Once `example.com` decides
  NewPQC wins, it drops the ML-DSA group from `createAlgs` and removes
  ML-DSA from `acceptedAlgs`:

  ```js
  acceptedAlgs: [
    alg["NewPQC-A"],
    alg["NewPQC-B"],
    alg["ES384"],
    alg["ES256"],
    alg["RS256"]
  ]
  createAlgs: [
    [
      alg["NewPQC-A"],
      alg["NewPQC-B"]
    ],
    [
      alg["ES384"],
      alg["ES256"],
      alg["RS256"]
    ]
  ]

  ```

  ```js
  acceptedAlgs: [NewPQC-A, NewPQC-B, ES256, RS256]
  createAlgs:   [[NewPQC-A, NewPQC-B], [ES256, RS256]]
  ```

  Existing ML-DSA credentials go dormant (inert, filtered out at
  `acceptedAlgs`) and may be swept via the Signal API exactly as the
  legacy ES256 credentials were in Example A. No user is locked out:
  every account already holds a NewPQC credential (or, on
  NewPQC-incapable hardware, a classical fallback) before ML-DSA is
  dropped.

* **Strategy can change per family.** ML-DSA might have had a
  standardized composite while NewPQC does not, or vice versa. Because
  the strategy is just "how many groups," the RP can run composite-style
  (one group) for one family and explicit-fallback-style (pure family
  plus a classical group) for another, and switch between them by
  reshaping `createAlgs` — without re-enrolling anyone.

The whole evaluation-and-migration sequence is a series of
configuration changes to `acceptedAlgs` and `createAlgs`. The flat
"mint one" alternative supports none of it: it can neither hold
multiple families for comparison nor pre-provision the next family
before retiring the current one.

## Security considerations

* **In-ceremony creation re-uses the assertion's user verification.** The
  user explicitly consented to a WebAuthn ceremony with `example.com`;
  binding additional keys for the same account to that same consent is
  not a privilege escalation. The UV gesture authorizes the whole
  ceremony's scope (this user, this RP, this moment), so there is no
  security difference between minting one credential and minting several
  under that single gesture. The platform UI SHOULD make clear that an
  account was "upgraded" when one or more silent creates happen, but no
  additional gesture is required.
* **Multiple credentials do not weaken the account.** Each credential is
  independently bound to the same `user.id` on the RP side. An attacker
  compromising any single key gains no more than they would in a
  deployment that only used that algorithm. The account's effective
  security is that of the *weakest algorithm in `acceptedAlgs` at the time
  of the attempted attack*, which is intentional and is the cost of
  pre-provisioning fallbacks against future algorithm failures. RPs that
  do not want to carry that exposure can keep `acceptedAlgs` narrow even
  while `createAlgs` provisions broadly — credentials minted but not
  accepted are dormant.
* **No autonomous eviction.** Silent creation MUST NOT evict any existing
  credential, on this account or any other. Storage pressure manifests as
  fewer silent creates, never as the disappearance of an unrelated
  credential. This is what makes group-shaped `createAlgs` safe for
  authenticators serving many RPs.
* **Algorithm downgrade by a hostile RP.** A compromised RP that ships
  `acceptedAlgs: [legacy]` could nudge clients away from a stronger
  algorithm. This is no worse than today: the RP already controls
  `pubKeyCredParams` and `allowCredentials`. The Signal API gives
  credential providers visibility into what the RP is actually willing to
  accept.
* **Asserter-binding of silently-minted credentials.** For every entry
  the authenticator places in `createdCredentials`, it also places a
  matching binding entry — `{id, pkHash, alg}` — in
  `authData.extensions.algPolicy.bindings` (§2 step 6). The assertion
  signature covers `authData`, so these bindings are cryptographically
  authenticated by the asserting credential — a credential the RP
  already trusts in this ceremony. Any party that can mutate
  `createdCredentials` in transit (a compromised browser extension, a
  compromised platform component, an unauthenticated
  authenticator-to-host transport, a malicious script between the JS
  context and the RP) therefore cannot substitute attacker-controlled
  public keys into the upload without also forging a matching binding,
  which it cannot do without the asserting credential's private key.
  The RP **MUST** discard any entry in `createdCredentials` for which no
  matching authenticated binding exists. The binding's strength is
  exactly the strength of the asserting credential's signature at the
  moment of minting; it does not protect against a future cryptanalytic
  break of the asserting algorithm (which would already grant an
  attacker the equivalent power via a fresh `create()` on the same
  account), and it is not a substitute for attestation — it does not
  authenticate the authenticator's make or model. What it does provide
  is **same-asserter provenance**: proof that the minted credentials
  came from the same authenticator that holds the credential the RP
  just authenticated against. That is the guarantee the silent-mint use
  case actually needs, and it is what makes shipping `attestation:
  "none"` for the mints (next bullet) safe.
* **Attestation conveyance is fixed at `"none"`.** Any entry returned in
  `createdCredentials` carries the same `AuthenticatorAttestationResponse`
  shape as `navigator.credentials.create()` would have produced, but the
  attestation statement is always anonymous. Provenance against
  in-transit substitution is supplied by the asserter-binding above, not
  by attestation — so the RP loses nothing it needs by foregoing
  attestation here. This is load-bearing for two independent reasons:
  the user authorized **sign-in**, not the disclosure of their
  authenticator's make and model, and there is no UI surface inside a
  `get()` ceremony on which to obtain attestation consent without
  defeating the silent-mint property; and allowing `"direct"` or
  `"enterprise"` here would create a fingerprinting vector — a
  compromised RP could harvest authenticator-identifying attestations
  from every signed-in user invisibly on the next ceremony after
  flipping the flag. RPs that require attested provenance for every
  credential (enterprise / regulated deployments) must drive users
  through an explicit `create()`; the silent-mint path is not designed
  for that posture.
* **Counter and clone-detection.** Each credential keeps its own signature
  counter; counters of distinct credentials are unrelated and MUST NOT be
  compared.

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

## Interaction with other features

* **Signal API** ([signal-api.md](signal-api.md)). The Signal API is
  the **sole mechanism** for retiring credentials under this
  extension. `algPolicy` itself never deletes credentials; old ones
  filtered out by `acceptedAlgs` sit dormant on the authenticator.
  When an RP wants to reclaim that storage — after a Phase 3 cutover,
  after an intra-group upgrade, or to revoke a specific compromised
  credential — it uses one of:
  - **`signalAllAcceptedCredentials`** (snapshot, per user): the
    natural fit for cutover cleanup. The RP sends the full set of
    credential IDs it considers valid for the user; the provider
    removes any other credential under `(rpId, user.id)`.
  - **`signalUnknownCredential`** (per credential ID): used for
    (a) sweeping orphans surfaced by `existingCredentials` so the
    next ceremony can re-mint and upload cleanly (see "Orphan
    credentials and convergence" in §3 — this is the most frequent
    use of the method in `algPolicy` deployments), (b) revoking a
    specific known-bad credential, and (c) targeted intra-group
    dormancy cleanup that must leave other users' instances of the
    same algorithm in place (e.g. drop Alice's now-redundant
    ML-DSA-65 while preserving Bob's, because Bob's authenticator
    does not support -87).

  Signal API delivery is reliable on synced and platform credential
  providers and best-effort on roaming authenticators. This is
  acceptable here because dormant credentials are inert (the RP
  filters them out at `acceptedAlgs`) and orphan-sweep failures are
  idempotent (the orphan resurfaces in the next ceremony's
  `existingCredentials` and the RP signals again). `algPolicy` itself
  never deletes credentials; any deletion runs through the Signal
  API, with the usual user/provider discretion.
* **Conditional create** ([conditional-create.md](conditional-create.md)).
  Conditional create lets an RP bootstrap a *first* passkey during a
  mediated password sign-in. `algPolicy` lets an RP add a *next*
  passkey during a passkey sign-in. The two are complementary and may
  coexist in a single deployment.
* **`get-client-capabilities`**
  ([get-client-capabilities.md](get-client-capabilities.md)). Two
  capability keys are useful here, mirroring the two-layer split: one
  for the top-level `acceptedAlgs` member (e.g. `"acceptedAlgs"`) and
  one for the silent-mint extension (e.g. `"algPolicy"`). An RP can
  legitimately depend on only one — e.g. ship `acceptedAlgs` to phase
  out an algorithm at sign-in without ever invoking silent mints — so
  detecting them independently lets the RP pick the right deployment
  phase.
* **`pubKeyCredParams` on `create()`** is unchanged. The new top-level
  `acceptedAlgs` on `get()` is its symmetric counterpart, not a
  replacement. RPs that prefer an explicit re-enrollment flow can
  still use `pubKeyCredParams` alone; this proposal is additive.

## Open questions

1. **`create()` parity.** Initial registration via
   `navigator.credentials.create()` still mints only a single credential.
   An RP running standing `createAlgs: [[PQC...], [ES256, RS256]]` will see
   new users start with one credential and acquire the second on their
   next sign-in. Should `create()` grow an analogous "also mint these"
   mechanism, or is the get-time backfill sufficient? The current
   proposal says backfill is sufficient.
2. **Placement of `acceptedAlgs`.** This explainer puts `acceptedAlgs`
   at the top level of `PublicKeyCredentialRequestOptions`, alongside
   `allowCredentials` and `userVerification`, on the grounds that it
   is the symmetric counterpart of `pubKeyCredParams` at `create()`
   and is a plain candidate-set filter independent of the silent-mint
   machinery. The alternative is to keep it inside the `algPolicy`
   extension. The top-level placement implies a CTAP edit to add
   `acceptedAlgs` as a **top-level `authenticatorGetAssertion`
   parameter** (so on-authenticator credential selection respects it
   even for a plain assertion with no minting), rather than as an
   `algPolicy` extension member — mirroring the WebAuthn-layer layering,
   where only `createAlgs`/`createExtensions` live in the extension (see
   "CTAP mapping" in §2). The trade-off is the heavier process weight of
   a top-level option versus an extension registry entry. The current
   proposal takes the top-level position.
3. **Conditional classical fallback on a heterogeneous fleet (a narrow
   residual).** The group model already handles "composite preferred,
   pure-PQC otherwise" cleanly by listing both in a *single* group,
   strongest-first: `[[ML-DSA-65-ECDSA-P384-SHA512, ML-DSA-65], [ES256, RS256]]`.
   On a composite-capable authenticator group 1 mints the composite; on a
   composite-incapable (but ML-DSA-capable) authenticator group 1 mints
   pure ML-DSA — one PQC credential either way, no redundant PQC
   credential, and an authenticator that later gains composite support
   self-upgrades via the best-supported rule. (An earlier draft of this
   explainer wrongly listed composite and pure-PQC as *separate* groups,
   which is what produced a redundant ML-DSA credential; the
   single-group form above is the right pattern.)

   The one thing groups cannot express is a *conditional second group*:
   "add the classical fallback group only on authenticators that could
   not mint a composite." A composite credential is its own
   emergency-downgrade target (it carries a classical leg), so the
   classical group is pure insurance for the pure-ML-DSA subset of the
   fleet — but if the RP lists it, composite-capable authenticators mint
   a redundant classical credential too. There is no cross-group
   "include this group only if an earlier group was unsatisfiable"
   dependency.

   Whether this matters depends on the RP:
   * **Uniformly composite-capable fleet, or content with pure-PQC-only
     on non-composite devices** → use a single group
     `[[ML-DSA-65-ECDSA-P384-SHA512, ML-DSA-65]]`, no classical group,
     zero redundancy, no gap.
   * **Heterogeneous fleet, and the RP wants the non-composite subset to
     carry a classical fallback** → add `[ES256, RS256]`, accepting one
     redundant classical credential per composite-capable authenticator
     (harmless and bounded, but not free on slot-constrained roaming
     keys).

   Whether a future revision should add cross-group conditionals to
   remove even that one redundant credential is open; the storage it
   saves is small.

## Useful links

* [Signal API explainer](signal-api.md)
* [Conditional Create explainer](conditional-create.md)
* [Get Client Capabilities explainer](get-client-capabilities.md)
* [IANA COSE Algorithms registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
