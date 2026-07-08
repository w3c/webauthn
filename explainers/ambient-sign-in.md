# Explainer: WebAuthn Ambient UI

## Author:

Ken Buchanan \<kenrb@chromium.org\>

_Last updated: 24-Jun-2026_

## Summary

This explainer describes an augmentation to [WebAuthn Conditional Mediation](https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Conditional-UI) that allows a Relying Party (RP) to trigger a WebAuthn sign-in flow when eligible discoverable credentials are available without a login form being present on the page. We are calling this enhancement Ambient UI.

User agents display the credentials to the user on an unobtrusive UI surface such as a bubble. Optionally, they can integrate other [Credential Management API](https://www.w3.org/TR/credential-management-1/) credential types such as passwords or [FedCM](https://www.w3.org/TR/fedcm/) into the same surface.

## Background and Use Cases

Conditional mediation allows WebAuthn to be integrated into the form autofill feature available on modern browsers. This allows RPs to provide WebAuthn-based sign-in on login pages that currently have username and passwords fields while avoiding modal WebAuthn dialogs for users who don’t have eligible credentials.

The motivation for this feature is to improve the sign-in experience when a user navigates to an arbitrary page on a site where the user has an existing account, but not an active signed-in session. Conditional UI is not useable because there is not a sign-in form on the page. Prompting a passkey sign-in with a modal dialog is not appropriate because the user has not expressed an intent to sign in at this point.

Examples:
* A user on a social media site clicks a link to a paywalled news article. The user has an account on the site hosting the article but not a valid signed-in session. The user sees and clicks a lightweight browser sign-in prompt and it completes a sign-in to unlock the page.
* A user uses a search engine to search for a category of product and then clicks a link to an e-commerce site where they have an account. The user is not signed in so the page shows generalized results. When the user signs in using the prompt, the results page changes to show more relevant products based on the history of previous purchases the user has made.

For a user with no eligible credentials for the site, no UI is shown. In this case, the returned Promise does not resolve, the same as is currently the case in Conditional UI.

![Bubble in top-right of browser window showing a WebAuthn credential](assets/ambient_ui_concept.png)

## API

Feature detection is provided by another enumeration value in ClientCapability: `ambientGet`.

When the request contains `mediation: "conditional"` and the PublicKeyCredentialRequestOptions contains `uiMode: "passive"`, the user agent displays discoverable WebAuthn credentials immediately in an unobtrusive UI prompt.

If the site wants to offer the Ambient UI prompt and also has a sign-in form on that page, the autofill behavior still works. That is, on a request with `uiMode: ‘passive’` if the user dismisses or ignores that UI but then clicks on a webauthn-tagged input field, the autofill UI will show the same as for any other `mediation: 'conditional'` request. Clicking a credential in the autofill UI behaves the same as clicking the same credential in the Ambient UI.

Example:
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

## Other Credential Types

Ambient behaves the same as [Federated Credential Management passive mode](https://w3c-fedid.github.io/FedCM/#dom-identitycredentialrequestoptionsmode-passive). Browsers that support both can offer them in integrated UI.

Requests for other credential types, such as [PasswordCredential](https://www.w3.org/TR/credential-management-1/#passwordcredential) can similarly be integrated into UI .
