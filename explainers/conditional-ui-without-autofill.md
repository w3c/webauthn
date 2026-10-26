# Explainer: Conditional UI without Autofill

## Author:

Ken Buchanan \<kenrb@chromium.org\>

_Last updated: 26-Oct-2026_

The most recent update introduced `uiMode: 'active'`.

## Summary

This explainer describes an augmentation to [WebAuthn Conditional Mediation](https://github.com/w3c/webauthn/blob/main/explainers/conditional-ui.md) that allows a Relying Party (RP) to trigger a WebAuthn sign-in flow when eligible discoverable credentials are available without a login form being present on the page.

User agents display the credentials to the user in a dedicated UI surface. Optionally, they can integrate other [Credential Management API](https://www.w3.org/TR/credential-management-1/) credential types such as passwords or [FedCM](https://www.w3.org/TR/fedcm/) into the same surface.

Two different variants are available. The RP can specify that the user agent should show credentials in a `passive` UI or an `active` UI, depending on whether the sign in option is intended to be a necessary step in the user flow or something that the user can ignore.

## Background and Use Cases

Conditional mediation allows WebAuthn to be integrated into the form autofill feature available on modern browsers. This allows RPs to provide WebAuthn-based sign-in on login pages that currently have username and passwords fields while avoiding modal WebAuthn dialogs for users who don’t have eligible credentials.

We have received feedback from RPs that there would be benefit in browsers being more proactive in initiating sign-in flows when those flows are easy and are very likely to result in success. In particular, users can be reluctant to explicitly initiate sign-in flows because of expected difficulty in doing so (e.g. remembering passwords, retrieving an SMS OTP from a phone, figuring out what authentication modality they have set up for this site). On sites where signing in is optional but can enable an improved experience for the user, this can discourage sign-in.

Consider when a user navigates to an arbitrary page on a site where the user has an existing account, but not an active signed-in session. Conditional UI is not useable because there is not a sign-in form on the page. Prompting a passkey sign-in with a modal dialog is undesirable because it obstructs the user experience if the user does not have a passkey for the site. A quiet prompt offering available credentials at this point provides a shortcut to the signed-in experience which the user might not have otherwise activated.

This feature can also be used on a sign-in page where Conditional UI is also available if the RP wants to provide a more prominent passkey sign-in option. Both UI surfaces can be available on the same page for a single request, but one displays immediately upon the request being made and the other depends on an autofill trigger.

This differs from [Immediate Mode](https://github.com/w3c/webauthn/blob/main/explainers/immediate-mediation.md) in that the returned promise does not resolve if there are no credentials available, and also in that it does not require a user activation. This mode is therefore suitable to be activated on page load without the user having interacted with the page.

Examples:
* A user on a social media site clicks a link to a paywalled news article. The user has an account on the site hosting the article but not a valid signed-in session. The user sees and clicks a browser sign-in prompt and it completes a sign-in to unlock the page.
* A user uses a search engine to search for a category of product and then clicks a link to an e-commerce site where they have an account. The user is not signed in so the page shows generalized results. When the user signs in using the prompt, the results page changes to show more relevant products based on the history of previous purchases the user has made.

For a user with no eligible credentials for the site, no UI is shown. In this case, the returned Promise does not resolve, the same as is currently the case in Conditional UI.

This proposal includes two different activation mechanisms that correspond to different UI experiences: 'passive' and 'active'. Passive conditional UI should initiate a quieter UI surface that is minimally disruptive to the user's current intention. Active conditional UI should initiate a louder surface, potentially modal and requiring user action to select a credential or dismiss it. RPs can specify the mode in the request, corresponding to which is more suited to the user's current point in their journey.

Example of potential passive UI:

![Bubble in top-left of browser window showing a WebAuthn credential](assets/conditional_passive_concept.png)

## API

Feature detection is provided by another enumeration value in ClientCapability: `conditionalPassiveGet`.

When the request contains `mediation: 'conditional'` and the PublicKeyCredentialRequestOptions contains `uiMode: 'passive'`, the user agent displays discoverable WebAuthn credentials immediately in an unobtrusive UI prompt.

If the site wants to offer the non-autofill Conditional UI prompt and also has a sign-in form on that page, the autofill behavior still works. That is, if the user dismisses or ignores the passive or active UI, but then clicks on a webauthn-tagged input field, the autofill UI will show the same as for any other `mediation: 'conditional'` request. Clicking a credential in the autofill UI behaves the same as clicking the same credential in the non-autofill UI.

Passive example:
```javascript
const cred = await navigator.credentials.get({
  mediation: 'conditional',
  uiMode: 'passive',
  publicKey: {
    challenge: ...,
    rpId: 'example.com',
    allowCredentials: {...},
  },
  password: true,
});
```

Active example:
```javascript
const cred = await navigator.credentials.get({
  mediation: 'conditional',
  uiMode: 'active',
  publicKey: {
    challenge: ...,
    rpId: 'example.com',
    allowCredentials: {...},
  },
  password: true,
});
```

## Other Credential Types

Conditional UI passive mode behaves similarly to [Federated Credential Management passive mode](https://w3c-fedid.github.io/FedCM/#dom-identitycredentialrequestoptionsmode-passive). Browsers that support both can offer them in integrated UI.

Requests for other credential types, such as [PasswordCredential](https://www.w3.org/TR/credential-management-1/#passwordcredential) can similarly be integrated into UI.

## Cross-origin iframes

Conditional UI is available in cross-origin iframes and the non-autofill modes should be available as well. User agents must take care to ensure that it is clear to the user what site the user is signing in to, exposing either the origin of the requesting frame or the RP ID of the request.

## Alternatives Considered

### No web platform change

User agents already have the ability to provide credentials in a dedicated non-autofill UI in response to a request with `mediation: 'conditional'`. Since Conditional UI is an established and widely used feature, we are concerned it would be unwelcome and disruptive to change the way it works in browser UI for all RPs. Adding a new `uiMode` value enables RPs to opt in to the alternative UI. 
