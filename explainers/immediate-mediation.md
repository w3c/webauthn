# Explainer: WebAuthn Immediate Mediation

## Author

Adem Derinel <<derinel@google.com>>

Ken Buchanan <<kenrb@chromium.org>>

Last updated: 02-04-2026

_A recent edit removed `immediate` as a `mediation` value, and added a new field called `uiMode`._

## Summary

We propose an “immediate” modality for WebAuthn and password `CredentialsContainer::get()` requests that mirrors the `preferImmediatelyAvailable` API properties on Android and iOS. This modality fails promptly if no credentials are immediately available, and thus allows sites to direct users to fallback sign-in methods or non-signed-in experiences in that case.

## Goal

This feature aims to enable a sign-in flow with passkeys and managed passwords that does not require a user to visit a traditional sign-in page containing multiple sign-in methods for the user to choose between (such as a username/password form, multiple federated sign-in options, a recovery button, etc), while at the same time not changing the sign-in experience for users for whom passkeys or managed passwords are not available. When one or more such credential are available, a user who has reached a sign-in moment in their interaction with a site (such as, for example, by clicking a "Sign In" button) will see a browser dialog containing a list of existing eligible credentials for that site. When the user confirms the credential to use (or selects a credential, if multiple are shown), they can be immediately signed in.

The use cases that this best supports are where a user has an account on the site, but the site does not know the identity of the user through previously set cookies. Some of the reasons why this commonly happens are:

* Users create an account and passkey for a site on one device, and want to sign in to the site on a different device, where the passkey has been synced by their passkey provider.
* The user is using a different browser on a device where they have previously signed in.
* The user is using the same browser, but a different profile.
* Cookies previously set by the site have expired.

## Background

WebAuthn currently provides two UI flows for sign-in:

* Modal: browser UI always appears. The returned promise resolves when the user exercises a credential or dismisses the UI.  
* Conditional: browser UI may appear, integrated with autofill on a form input field. The returned promise only resolves if the user selects a credential and completes the authentication ceremony.

The `preferImmediatelyAvailable` option on mobile platforms provides a lower-friction flow when there is an eligible credential. In that case it immediately displays UI containing available credentials, but if no credential is available then it returns an error so that the calling application can provide alternative sign-in methods. This is similar to conditional UI on the web, but in that case the relying party does not learn whether a credential is available and therefore has to provide all sign-in options on a single surface.

For a site where only a fraction of users have WebAuthn credentials, WebAuthn has no great answer for sites that want to implement a “Sign-in” button. This also helps us move toward the original design of Credential Management API and support sites making `get()` requests that accept credentials of any of several supported types, including WebAuthn, passwords, and federation.

![Current modal WebAuthn flow for a user with no local WebAuthn credentials. Whether it is the modal flow or the conditional flow, this may result in offering hybrid flow to the user.](https://github.com/user-attachments/assets/f4442367-4ce8-4096-90f8-89ac65837619)

*Current modal WebAuthn flow for a user with no local WebAuthn credentials. Whether it is the modal flow or the conditional flow, this may result in offering hybrid flow to the user.*

### Comparison to Conditional UI

Immediate is useful in many of the same situations that Conditional UI is, or can be, already used. Specifically: If the site is providing the user a chance to sign in, and it doesn't already know what authentication method the user will use, then both of these modalities options are useful. The advantage that Immediate provides is that it allows sign-in to be offered without presenting the user with all supported authentication options. Typically today this is a form with one or two input fields, and some number of alternatives.
<p align="center">
<img width="500" height="500" alt="Typical sign-in widget with username/password fields, a passkey button, a federated login button, and a password recovery option" src="https://github.com/user-attachments/assets/a4380abf-75af-45e9-93f5-d3c5e8ad6b87" />
</p>

Conditional UI has proven helpful to users on such UI, because autofill highlights easy sign-in options. Immediate, however, negates the need to show that at all.

#### Is this a polyfillable experience without adding a new mode?

Aside from typical existing sign-in experiences, many sites use more streamlined flows. There is also a question of how closely a site can build an Immediate-like experience using Conditional UI. The image below is an imagining of a dynamic sign-in widget drawn by the page, using Conditional UI.
<p align="center">
<img width="500" height="281" alt="A minimal sign-in widget containing a username field and an account recovery option. There is an autofill popup over it offering a passkey and a federated login option." src="https://github.com/user-attachments/assets/6cbb9898-e10c-44a2-b941-0fec4f4a74ad" />
</p>

> Note that providing a federated login option within autofill UI is not something that currently exists on the web, but it is a possible future exploration toward the goal of simplifying sign-in UI.

If such a widget is drawn dynamically after a user clicks a "Sign In" button then that UI would approximate what Immediate is intended to achieve. But the site still has to be showing all fallback options, or at least have a button that the user would have to click to find them, because it doesn't know if Conditional UI is actually showing anything.

More importantly, a fundamental constraint of Conditional UI is that it only works with a form input field, which is limiting not just in the visual experience but also in the use cases where it is appropriate. Immediate would remove the necessity of anchoring sign-in flows to textboxes.

#### Contextual sign-in moments

An example of a use case where that limitation becomes a problem is in the [Example Use Cases section below.](#example-use-cases). If a user is shopping on an e-commerce site without having logged in and initiates a checkout flow, the most common approach is to show a large form. This form can contain sign-in fields for users with existing accounts, but also fields for personal information such as address and phone number for users who will proceed to make a purchase without an account.
<p align="center">
<img width="500" height="510" alt="A checkout form that contains an option for signing in with a username and password, or else has many fields for manual entry of personal information necessary to complete the purchase." src="https://github.com/user-attachments/assets/efbc40ce-72cb-4e12-a7dd-43ab83c53fbf" />
</p>

Below shows a flow that Immediate can enable. Given the amount of information that is required if the user cannot sign in, this is not something that can be polyfilled as a regular sign-in might.
<p align="center">
<img width="350" height="350" alt="A shopping cart screen on an e-commerce site showing a running shoe in the cart, and a checkout button." src="https://github.com/user-attachments/assets/b711172c-fa50-4b56-9d9c-eeaa0d18e851" />
<img width="350" height="350" alt="A chopping cart screen on an e-commerce site showing browser UI with a passkey that the user can choose to sign in." src="https://github.com/user-attachments/assets/63fa11a6-b845-413f-a0e0-f9f36e8c009d" />
<img width="350" height="350" alt="A checkout screen with fields pre-populated from the user having signed in. There is a button to confirm and pay." src="https://github.com/user-attachments/assets/93f74908-2bb9-4e81-959b-f8677a86382b" />
</p>

There are numerous situations where a user can be interacting with a site and reach a point where a sign-in will significantly improve their experience if it is available, but the site can still provide a fallback experience if it is not. Another example could be a user on a newspaper's homepage who clicks a paywalled article, and an Immediate sign-in would be better than seeing a truncated article with an account overlay. Or a user starts playing a video on a video-sharing site which play without embedded ads if they are signed in to their account.

## API

We propose adding a new field to [CredentialRequestOptions](https://www.w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions) called `uiMode`. `uiMode` initially has one value, `immediate`, which provides the UI behavior described below.

> Note: Previous revisions of this explainer suggested that `immediate` could be a new value for the `[CredentialMediationRequirement](https://www.w3.org/TR/credential-management-1/#enumdef-credentialmediationrequirement)` enumeration, which would match how `conditional` is used. However, we have some concerns that this might limit flexibility as different UI options are added and also as more credential types become possible to be displayed together. The original intent of `mediation` was to specify whether or not the browser should show sign-in UI to the user. Adding `uiMode` to `CredentialRequestOptions` provides a way to specify what UI should be shown, in the cases where it is shown.

When `uiMode` is `immediate`, the returned promise resolves with `NotAllowedError` when there are no locally-available credentials; otherwise, the browser handles the authentication ceremony with those credentials as usual. Browsers can also throw `NotAllowedError` for other reasons, such as time constraints. (See Privacy section, below.)

```javascript
// Use `getClientCapabilities` for feature detection
let immediateModeAvailable = false;
if (window.PublicKeyCredential && PublicKeyCredential.getClientCapabilities) {
  const capabilities = await PublicKeyCredential.getClientCapabilities();
  // `immediateGet` is a new capability for immediate mode:
  immediateModeAvailable = capabilities.immediateGet === true;
}

if (immediateModeAvailable) {
  try {
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: ...,
        rpId: 'example.com',
        allowCredentials: [],
      },
      uiMode: 'immediate'
    });
  } catch (error) {
    if (error.name === 'NotAllowedError') {
      // handle the no credential or cancellation case
    } else {
      // other cases
    }
  } 
}
```

### **Supporting cross-device authenticators**

The UI associated with this API will only show credentials that are known to the user agent or can be discovered without user action. Typically this will not include credentials stored on security keys or on mobile devices, which would be usable through the hybrid transport. We note that:

1. If a security key and the platform both support CTAP 2.2 credential enumeration, those credentials can be considered to be immediately available.  
2. Sites will have to support another way to use WebAuthn credentials because, as noted in the Privacy section, we expect this API to always fail in Incognito/private browsing contexts.

When security key credential enumeration is not available, the sign-in experience for users using security key credentials will typically remain unchanged. No UI will be shown from this call unless there are also credentials from that site available from a platform authenticator, after which the user will proceed to the site's sign-in page.

### **Other credential types**

On supported browsers, password credentials (i.e. `navigator.credentials.get({password: true})`) return immediately when there are no passwords available.

Federated credentials and passwords can also support immediate mode if needed to make a more coherent sign-in flow. With the increased support, relying parties can choose which credential type they want to use as the “primary” sign-in flow and implement the follow-up authentication methods as backup.

While not addressed in this explainer, a future direction of requesting WebAuthn, federated and password credentials together could look like

```javascript

try {
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: ...,
      rpId: 'example.com',
      allowCredentials: [],
    },
    identity: { ... },
    password: true,
    mediation: "required",
    uiMode: "immediate"
  });
  // Site will also show a button to trigger a modal flow
  // to handle Incognito and security key users
} catch (error) {  
  if (error.name === 'NotAllowedError') {
    // No immediate WebAuthn, federated or password credentials found, or 
    // the user dismissed the browser UI.
    // The relying party can fallback to their preferred solution such as
    // asking the user's phone number / email.
  } 
}
```

## Example use cases

Consider a relying party with an existing user base. They want to use a passkey as easily as possible for users that have them, but users that don’t have passkeys should see the standard sign-in UI. 

The relying party’s goal is to provide a frictionless sign-in experience, minimizing confusion and unnecessary steps. They want to avoid overwhelming users with multiple sign-in options, especially those unfamiliar with passkeys. 

Here's how the relying party could use the new API to achieve this:

1. User navigates to the main page of the website (e.g. a shopping page).  
2. Upon page load, and after a user gesture (such as clicking a "Sign In" button), the relying party calls `navigator.credentials.get` with a `PublicKeyCredentialRequestOptions` object and `uiMode: ”immediate”`. They may also include `password: true` in the request.  
3. The browser checks the local authenticators for any local credentials. Ideally, this would be near-instantaneous.  
4. If there are no local credentials  
   1. The browser throws a `NotAllowedError` to the relying party.  
   2. The relying party asks the user for more details (e.g. email address)  
   3. The relying party shows the alternative authentication mechanisms such as a password form, SMS OTP, or the WebAuthn hybrid flow. They can also offer to create a passwordless account if the user details are not in their system.  
5. Otherwise (if there are local credentials):  
   1. The browser presents the required UI to the user for authentication.

![Example flows: If there are WebAuthn credentials (or passwords) locally, browser UI will prompt the user to select one. The user can choose another way in the browser UI to fallback to the sign-in / sign-up page. In the case of no WebAuthn credentials locally, the website should show the existing sign-in / sign-up page.)](https://github.com/user-attachments/assets/75f5f9c1-3ae8-4db2-857e-6852ebbd9382)

***Example flows:** If there are WebAuthn credentials (or passwords) locally, browser UI will prompt the user to select one. The user can choose another way in the browser UI to fallback to the sign-in / sign-up page. In the case of no WebAuthn credentials locally, the website should show the existing sign-in / sign-up page.*

## Privacy considerations

Currently the RP does not have a way to learn about the availability of WebAuthn credentials until the user interacts with browser API, authorizing the generation of an assertion. Under this proposal that would change, enabling the RP to learn about the presence of immediately available credentials without such an authorization. This is because if UI is shown, the site can detect that by measuring the time before the promise resolves.

Specifically:

* If UI is shown, the promise takes more than a short time to resolve, indicating that the user is being offered sign-in credentials for the site. If the user chooses not to select a credential for sign-in, the site still obtain the information that at least one credential exists.
* If no UI is shown, the promise returns quickly. This can indicate that the user has no credential, although there are other reasons why UI might not have been shown so the conclusion would be less clear.

The site would not learn any information about the contents of a credential (in particular, any identifying information) unless and until an assertion is returned (after the use has provided consent), but the single bit available from the API returning immediately with a `NotAllowedError`, or having a long delay due to UI being shown to the user, represents a relaxation of WebAuthn privacy protections.

Potential consequences of this include:

* User fingerprinting risk -- e.g. a single bit of information about a client can be combined with other available client-distinguishing information to attempt to identify users
* Sites pressuring users with accounts to sign in -- there is a potential for sites to offer different experiences for users who don't have accounts compared to those who do have an account and have not signed in

We propose the following measures to mitigate the potential for abuse of that relaxation:

### **User gesture requirement**

To mitigate silent probing of credential availability and fingerprinting, we will require a user gesture before this API call can be made. The user gesture could be [any transient user activation](https://developer.mozilla.org/en-US/docs/Web/API/UserActivation). In particular this requirement makes it difficult for a site to do many calls with varying RP IDs. Calling this API does not consume the user gesture so that the gesture will still be available if the site wants to perform another operation that requires one.

### **Rate limiting**

User agents should limit the number of times this API can be called on a page in a given amount of time.

### **Incognito and private sessions**

In incognito or private browsing sessions, any immediate mode request should throw `NotAllowedError`. This is similar to the user having manually cleared cookies. To avoid incognito fingerprinting, this response can be delayed by the browser to simulate the browser fetching credential metadata from the system. A call made in an private session should be indistinguishable to the site from a call made in a normal session where no credentials exist, even using precise timing measurements.

### **Request with allowlists**

Requests with allowlists should throw `NotAllowedError`. If a relying party queries for a list of credentials and gets a response indicating one exists, this could be used to infer whether the user has previously interacted with the site. Over time, this could allow tracking of users across different sessions. 

### **Cancellation**

Setting the `signal` parameter on a request with immediate mode is invalid as sites should not be able to programmatically dismiss any browser UI.

## Similar systems

Both Android and iOS APIs support immediately available credential calls for sign in. Android Credential Manager will respond with `NoCredentialException` similar to `NotAllowedError` DOMException when the sign in request prefers immediately available credentials but none are available.

## Alternatives considered

### Not resolving the promise when no credentials are present

Conditional UI will not resolve the promise if there are no credentials available for display, and this mode might be better for privacy if it behaved similarly. In that case, this would represent a modification to Conditional UI that shows a modal dialog and does not depend on a form being present.

It is possible that a separate mode with that behavior could be added, but it would not meet a primary use case this mode is intending to support, which is to support sign-in while remaining in the current web page context.

### Hiding user credentials when cookies have been cleared

One suggestion was that when a user clears browsing data in their client, it should be taken as a signal that they want to be anonymous to the websites they are visiting, unless they actively sign in again. In that case it would make sense to actively hide the existence of credentials, as is done in private browsing mode.

However it is not clear that this is the most common reason for users to clear browsing data. Often this is a step taken by users when a web site is not behaving correctly. In that case a lower-friction passkey-based sign-in is beneficial as a way to help them get back to a good state.
