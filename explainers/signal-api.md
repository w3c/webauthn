# Explainer: WebAuthn Signal API

_(note: renamed from "Report API" to avoid confusion with the [Reporting API](https://developer.mozilla.org/en-US/docs/Web/API/Reporting_API))_

## Authors

@arnar, @nsatragno

## Objective

Allow WebAuthn relying parties to report information about existing credentials back to credential storage providers, so that incorrect or revoked credentials can be updated or removed from provider and system UI.

## Background and motivation

Discoverable credentials, such as passkeys, can be requested with `navigator.credentials.get` with an empty `allowCredentials`. In this case, if a user has any credentials for that relying party, they are presented with some UI to select which credential to use. If the user selects a credential, the resulting assertion carries the `user.id` value set at registration, allowing the relying party to resolve to an account without any further information.

This allows flows where the user is not required to enter a username, they simply select a credential. When used with conditional mediation, this further allows a smoother transition from traditional username entry, by allowing users that have passkeys to "fill" the username field using the passkey, and usually thereby omitting any further entry such as passwords or 2nd-factor authentication.

In such UI, passkeys are represented by the `user.name` and/or the `user.displayName` values that the relying party specified at registration. The user sees the entries as if they are _accounts_, however the entries correspond to individual credentials.

This pattern poses two main problems, given the current available APIs.

1. If a relying party stops accepting a credential, e.g. as a result of revoking it from an account or by completely deleting an account, the credential is still presented by clients during discoverable flows. 
2. Even if relying parties allow a user to change their username or display name on the account, such changes are not reflected in the display of credentials during discoverable flows.

The first case in particular is not only tied to explicit revocation or account deletion as requested by users. RPs may have policies that require them to revoke credentials after periods of inactivity. A common problem is also that the same user ends up with multiple accounts on a single RP unintentionally and may have a hard time keeping track of which accounts they want to use. Here the solution of account deletion or consolidation misses the mark if it cannot be represented in credential selection UI.

## Non-goals

Signal methods do not allow credential providers to update information stored by relying parties (e.g. if a user changes or deletes a credential from their credential manager settings).

Signal methods do not allow relying parties to query the availability, name, or display name of existing credentials.

## Solution

A new set of methods, `PublicKeyCredential.signal*`, allow relying parties to report such state updates back to user agents, who can forward these to the underlying credential providers. The API is opportunistic as there is no guarantee that the correct credential provider is reachable on the current client. Note that any credential provider action is optional and at the discretion of each provider implementation.

`PublicKeyCredential.signal*` methods return a promise that will reject if there are any errors parsing a report (e.g. an invalid base64url string, or claiming an invalid RPID). However, the result will not include any information about how a report was processed. This is to allow for implementations that do not collect consent from the user before e.g. updating a credential's name without leaking leaking information to the RP about the state of the credentials.

### `PublicKeyCredential.signalUnknownCredential`

This method names a credential ID and indicates that the relying party would reject an assertion with that credential because the credential ID is unknown to the RP.

```javascript
PublicKeyCredential.signalUnknownCredential({
  rpId: "example.com",
  credentialId: "vI0qOggiE3OT01ZRWBYz5l4MEgU0c7PmAA" // b64-url cred ID
});
```

_Usage scenario:_ Immediately following a response from `.get()` where the credential ID was not recognized. Appropriate to report even if the user was not authenticated.

_Example provider action:_ The credential may be marked for omission from future credential selection UI. If it was recently created and overwrote an existing credential, the previous one might be restored.

This situation may arise, for example, because the credential was revoked, or because the RP performed a create operation but failed to successfully store the public key on its backend.

### `PublicKeyCredential.signalAllAcceptedCredentials`

This report names a `user.id` value and all accepted credential IDs.

```javascript
PublicKeyCredential.signalAllAcceptedCredentials({
  rpId: "example.com",
  userId: "M2YPl-KGnA8",  // b64-url
  allAcceptedCredentialIds: [
    "vI0qOggiE3OT01ZRWBYz5l4MEgU0c7PmAA",  // b64-url
    ...
  ],
});
```

_Usage scenario:_ Immediately after an accepted `.get()` response, or at any time the user is authenticated and the set of accepted credentials has changed.

This report should only be made if the user has been fully authenticated.

_Example provider action:_ Mark any non-appearing credential for the same RP ID and `user.id` value for omission in future account selectors. Remove the mark from credentials that appear in the list.

Note that it's at the provider’s discretion whether to hide or permanently delete credentials that aren't present in the list.

### `PublicKeyCredential.signalCurrentUserDetails`

This report names a `user.id` value, a `name` and `displayName`.

```javascript
PublicKeyCredential.signalCurrentUserDetails({
  rpId: "example.com",
  userId: "M2YPl-KGnA8",  // b64-url
  name: "a.new.email.address@example.com",
  displayName: "J. Doe"
});
```

_Usage scenario:_ Immediately after an accepted `.get()` response, or at any time the user is authenticated and their `name` or `displayName` have changed.

This report should only be made if the user has been fully authenticated.

It is not possible to update the `user.id` value.

_Example provider action:_ Update the credential store to use the supplied values in future UI representing this credential.

Note that it's at the provider’s discretion how to handle conflicts between manually edited usernames/displayNames and the RP-provided reports.

## Examples

### A user updates their username with a site

A user changes their username with a site, e.g. through the site settings. The user has passkeys. Before the signal* methods, the only option to keep the passkeys `user.name` attribute in sync with the site would be for the user to manually visit their credential providers settings and change the value themselves. Otherwise, on sign-in, the wrong information would be displayed, leaving the user confused at best and frustrated at worst.

With the signal method, as soon as the user updates their username, the site calls:

```javascript
await PublicKeyCredential.signalCurrentUserDetails({
  rpId: "example.com",
  userId: "M2YPl-KGnA8", // same as user.id at creation time
  name: "newusername",
  displayName: "New Display Name"
});
```

The next time the user signs in, the browser will offer credentials with a name that match the newly chosen name.

### A user removes a credential from a site

A user removes a credential from a site, e.g. through the site settings. Before the signal methods, if the user did not go through their credential provider settings to manually remove the same credential, the credential provider would still offer it on sign-in. This would be confusing (after all, the user removed the corresponding entry on the site!) and attempting to use that credential would result in the site returning an error.

With the new signal methods, after a credential is removed, the site can call

```javascript
await PublicKeyCredential.signalAllAcceptedCredentials({
  rpId: "example.com",
  userId: "M2YPl-KGnA8", // same as user.id at creation time
  allAcceptedCredentalIds: [
     // IDs of all accepted credentials, minus the credential that was removed
    "vI0qOggiE3OT01ZRWBYz5l4MEgU0c7PmAA",
    "Bq43BPs"
  ]
});
```

This will result in the browser notifying the credential manager, which can then remove or hide the credential from future sign in attempts.

If the user revokes or deletes a credential, e.g. in an account settings UI on the relying party's website, the relying party can opportunistically report this at that time with `signalUnknownCredential`. However this will only have effect if the user agent is able to route the report to the same credential provider that created this credential. It may be better to send a `signalAllAcceptedCredential` report instead, with a complete list of valid credential IDs.

### A user attempts to sign in with a credential that is no longer valid

If a relying party receives an assertion with a credential that it does not recognize, it can report this back to the client. Note that it is safe to do this even if no user is signed in, as long as the credential id was already observed from this client.

```javascript
await PublicKeyCredential.signalUnknownCredential({
  rpId: "example.com",
  credentialId: "vI0qOggiE3OT01ZRWBYz5l4MEgU0c7PmAA"  // b64-url
});
```

Then the user agent can inform the user that the credential is not valid and delete it or hide it from new sign in attempts. This situation can happen if e.g. the user removes the credential on the site using a browser or device that does not have access to that credential, or if the site chooses to revoke the credential for policy reasons. Before the signal methods, the credential would have been offered to the user for as long as they did not manually remove it using their credential manager settings.

## Alternatives considered

### Tell sites to override credentials instead

If a site creates a new credential on a provider for the same `user.id`, any existing credential would have been overwritten. In theory, this could be used instead of the `signalCurrentUserDetails` method. However, this approach is fraught:

* From the perspective of the browser, this is no different to creating a new credential, so the UI can be very confusing as it appears to the user that they are making a new credential as opposed to updating an existing one.
* There is no way for sites to restrict the operation to credential providers the user already has a credential for. Therefore, it's possible a user accidentally chooses a different credential provider and really does create a new credential instead.
* The site and user would have to go through this process for every credential they have associated to a site.

### Design the signal methods so they return success or failure

During early design, we considered having the signal methods return whether credentials were updated or not. This would help sites tailor the experience after calling the methods. However, this would also reveal the existence of credentials to the site, so it would require some form of confirmation from the user. We decided against returning any information on the status of the invocation to avoid the need to prompt the user.
