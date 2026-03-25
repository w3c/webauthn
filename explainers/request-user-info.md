# Explainer: WebAuthn `requestUserInfo`

**Author**: Nina Satragno <nso@google.com>

**Status**: Draft

## Summary

A new option for credential creation that requests a user's identifier and name alongside the credential to aid relying parties in account creation.

## Background and motivation

We are seeing widespread adoption of passkeys on all sorts of relying parties, with far better outcomes than traditional password based sign-ins. Passwords are starting to be displaced in some applications, with Microsoft [allowing users to delete their passwords](https://support.microsoft.com/en-us/account-billing/how-to-go-passwordless-with-your-microsoft-account-674ce301-3574-4387-a93d-916751764c43), and Apple [providing an API that lets apps mark passwords as unused](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller/reportunusedpasswordcredential(fordomain:username:)?language=objc).

However, we aren't seeing relying parties start their users with passkeys from the get-go. Every sign up flow out there is based on either federation, email verification, or passwords. The latter two usually involve cumbersome form filling where the best help user agents can give the user is based on autofill heuristics. Federation often requires fewer steps, but it comes at an additional privacy cost, and a dependency on identity provider's account policies that not every relying party wants. With federation, relying parties also have to individually support identity providers.

The Chrome WebAuthn team proposes an addition to the WebAuthn API that will enable streamlining the account creation process. Developers who integrate the API will obtain a passkey and a set of user attributes. The design is such that it can be readily extended to support verified emails. We hope that this makes signing up a breeze for users, drives adoption across all passkey providers, and moves us closer to a truly passwordless world.

## Design

### Requesting attributes

Relying parties will be able to pass a list of predetermined information to obtain in a request via a new `requestUserInfo` `PublicKeyCredentialUserEntity` attribute. These will be divided into identifiers and attributes. Sites may ask for one of a number of possible identifiers, but they may get only one. Conversely, all attributes requested are considered required.

The initial list of identifiers is:

- phone
- email

And the list of attributes is:

- name

It is impossible then to ask for both a phone and an email, to nudge developers away from requesting more information than they need just because they can. For the same reason, all non-identifier attributes are required, this is to say, there is no way to indicate that an attribute may be omitted.

For example,

```javascript
navigator.credentials.create({
  publicKey: {
    user: {
      id: ...,
      name: "",  // Intentionally left empty.
      displayName: "",  // Intentionally left empty.
      requestUserInfo: {
        identifiers: ["phone", "email"],
        attributes: ["name"],
      }
    }
  }
});
```

Could result in the browser rendering something like this:

```text
+------------------------------------------+
| Create an account on example.com?        |
| You'll share this information:           |
|                                          |
| [marisa@example.com] [use phone instead] |
| [Marisa Kirisame]                        |
|                                          |
| [Cancel]                          [OK]   |
+------------------------------------------+
```

Attributes will be returned as an object with a mandatory value field. In the future, these can be augmented with verification signals.

```javascript
userInfo: {
  identifier: {
    type: "email",
    value: "marisa@gmail.com",
  },
  attributes: {
    name: {
      dir: "ltr",
      language: "en-CA",
      value: "Marisa Kirisame",
    },
  }
},
```

The order of the identifiers and attributes is important and serves as a browser hint for displaying on the UI.

### [`user.name`](https://w3c.github.io/webauthn/#dom-publickeycredentialentity-name) and [`user.displayName`](https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-displayname)

The chosen identifier will be used as the credential's user [`name`](https://w3c.github.io/webauthn/#dom-publickeycredentialentity-name) and [`displayName`](https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-displayname) attributes, so there is no need for developers to pass a `user.name` or `user.displayName` value.

User agents already know their users very well. Thus, attributes will not be sourced from the authenticator, but from the user agent, similar to how autofill works.

### Feature detection

The availability of this functionality and list of attributes must be detectable by the relying party. We'll extend `ClientCapabilities` to reflect each attribute:

- `userInfoIdentifierPhone`
- `userInfoIdentifierEmail`
- `userInfoAttributeName`
  
These will list the user attributes that may be requested. If at least one of these is present, then `requestUserInfo` will be usable.

### Error handling

There will be two distinguishable error types returned by the API:

- `InvalidStateError` when the user cancels out of the dialog. This should be interpreted as the user does not want to sign up for the site, by e.g., redirecting the user to the homepage.
- `NotAllowedError` for all other errors where the user may still want to create an account but the browser can't do it either because there are no suitable authenticators available or there was some problem with the authenticator. In this case, the site should redirect the user to a traditional form-based account creation form.

### User activation requirement

Unlike regular WebAuthn requests, this API will reveal some information about a user who's never been to a site before. To avoid making browsing the web noisier than it already is, this API will be gated by a user activation requirement.

### UI redressing protection

Unlike regular WebAuthn requests, this API will reveal some information about a user who's never been to a site before. User agents should take [UI redressing](https://w3c.github.io/webauthn/#ui-redressing) ("clickjacking") into account when designing their user interfaces.

### Testing

The [virtual authenticator](https://w3c.github.io/webauthn/#sctn-automation) will be extended to support seeding user attributes.

### Cross origin iframes

It's already possible to create passkeys on cross origin iframes with the correct permissions policy. Perhaps then this feature should probably be supported in that scenario as well.

## Relying party actions

Relying parties should first feature detect the API. If either the API or the attributes they require are not supported, the relying party should proceed with a form-based sign-up form.

Assuming support, relying parties should install a click handler on their "sign up" button. On click, they'll either fetch a challenge and user ID or generate them on the client, then call the WebAuthn API with the new parameters.

```javascript
// sign_up_button_handler.js:

// Feature detection.
let capabilities = await PublicKeyCredential.getClientCapabilities();
if (!capabilities["userInfoIdentifierEmail"] ||
    !capabilities["userInfoAttributeName"]) {
  proceedWithFormBasedSignUp();
  return;
}

// Fetch dynamic parameters from the server, or generate them locally on the client.
let serverParams = await fetch("new-user/webauthn-params.json");

// Perform the WebAuthn request.
let credential;
try {
  credential = await navigator.credentials.create({
    publicKey: {
      challenge: serverParams.challenge,
      pubKeyCredParams: { type: "public-key", alg: -7 },
      rp: { name: "Example RP" },
      user: { 
        id: serverParams.userId,
        name: "",  // Intentionally left empty.
        displayName: "",  // Intentionally left empty.
        requestUserInfo: {
          identifiers: ["email", "phone"],  // name & displayName will match email/phone.
          attributes: ["name"],
        }
      },
  });
} catch (error) {
  if (error.name === "NotAllowedError") {
    // The user failed to verify their identity or some other error occurred.
    showErrorThenProceedWithFormBasedSignUp();
    return;
  }
  if (error.name === "InvalidStateError") {
    // The user does not want to sign up.
    goToHomeScreen();
  }
  // Getting here would likely indicate a bug.
  throw error;
}

let response = await fetch("new-user", { method: "POST", body: credential.toJson() });
if (response.ok) {
  // New user account created.
  window.location = "main-content.html";
  return;
}
if (response.error == "user already has an account") {
  handleUserAlreadyHasAccount();
}

// Handle other errors.
```

Relying parties can then create a new account with the result of the response.

### Handling existing accounts

Relying parties should try to avoid a situation where they call this API when the user already has an account, e.g. by using [`immediate` mediation](https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-immediate-mediation) on page load. There is unfortunately no way around the fact they will need to handle the case where a user already has an account, and the browser just created a passkey for them.

Relying parties can detect this situation by comparing the user's identifier (email or phone number) with their user database on response. To remediate the situation, one option is to use the [signal API](https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Signal-API-explainer) to delete the passkey that was just created with signalUnknownCredential, then prompt the user to sign in with their preferred method.

## Alternatives considered

### Allow the API to return an assertion if there's an existing credential

An interesting approach would be to allow the API to return an assertion, especially if the user already has a credential for a matching username. The browser could list credentials from all providers, offer those, and have a button that says "No, I really want to create a new account". This would prevent the subset of existing accounts where a passkey is present for an available provider. With this approach, sophisticated relying parties could implement a more advanced flow:

- Call the WebAuthn account creation API.
- If that returned an assertion, sign the user in.
- Otherwise, if this is a new user, create an account.
- Otherwise, this is an existing user, and we are pretty sure that the newly minted passkey is not a duplicate on their provider:
  - Keep the passkey public key and user ID around.
  - Authenticate the user through some other means.
  - If that fails, use the signal API to clean up the passkey.
  - Otherwise, associate the newly created passkey and user ID to the user.

This flow would require relying parties to track multiple user IDs per user, but allows associating the newly minted passkey to an account.
Unfortunately, this makes for a much more complicated API for browsers and relying parties to implement. And, it's obsoleted by immediate mediation getting to a point where it's reliable most of the time.

### Separate the API into two phases

One alternative design is to separate the account creation API into two phases. The initial phase would request the list of attributes. Then, if the relying party wants to move forward with the account, another call would silently create a credential. An example of such a flow would be:

```javascript
// Feature detection.
if (!window.UserAttributes) {
  proceedWithFormBasedSignIn();
  return;
}

// Obtain the attributes.
let userAttributes = await navigator.credentials.get({
  userAttributes: ["email", "name"],
});

let response = await fetch(
  "new-account/attributes", { method: "POST", body: userAttributes.toJson() });
if (response.error) {
  if (response.error == "user already has an account") {
    redirectToSignIn();
    return;
  }
  // Handle other errors.
  return;
}

// Proceed with creation of a passkey.
let credential = await navigator.credentials.create({publicKey: {
  mediation: "conditional",  // Suppress UI.
  ...
}});

let passkeyResponse = await fetch(
  "new-account/" + userAttributes.email + "/passkey",
  { method: "POST", body: credential.toJson() });
```

This approach has the advantage that it simplifies handling of existing accounts, since there is no passkey to clean up left on the provider.

However, it was discarded because it makes it impossible for the browser to accurately obtain consent for the creation of the passkey, and because the goal of the API is not just to create a generic sign up API. Supporting passkeys is the point. Let's explore two avenues one may suggest this sort of flow:

#### The user agent asks for consent to create a passkey during the first request

This approach would have the browser show UI just like in the actual proposal, with all the steps required to create a passkey. But a passkey would not actually be created until the follow-up create request. Conceptually, this isn't that different to the actual proposal in the "normal" case.

The main disadvantage of this approach is that the browser has no way to know if the relying party will actually proceed with creation. I doubt we would be able to concisely communicate to a user that they are consenting to something that may or may not happen. The silent create call would also be subject to heuristics in terms of when to allow it (e.g. if too much time passed between calls, it may be rejected), adding another failure point.

#### The user agent does not mention passkeys during the first request

The idea is that the browser says nothing about passkeys during the first request, then silently creates a passkey.

This has two disadvantages:

- There is no way to get consent for storing a passkey for the user. Regular conditional create calls assume consent by virtue of an existing credential on the user's password manager, but by definition we won't have that during sign-up.
- We would be shipping a generic "give me attributes about the user" API, which is not the stated goal for this proposal.
