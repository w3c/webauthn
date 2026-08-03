# Explainer: WebAuthn Conditional Create

**Author:** Pascoe <[pascoe@apple.com](mailto:pascoe@apple.com)>

**Last update:** January 16, 2025

## Summary

A WebAuthn assertion extension that lets relying parties register a credential while a conditional mediation assertion is running.

## Background

Relying parties often have both users with passwords and users with passkeys. Conditional mediation on assertions allow user agents to mediate authentication ceremonies for both passwords and passkeys. If a user has a password, but not a passkey, a relying party might want to create a passkey, but not know when to do so. The user agent may have information about whether or not a user has a passkey. This extension provides a way for relying parties to signal to the user agent that it wants a passkey for a user completing mediated password login.


### Example use case

A consumer RP uses username and password login for most of their users. The relying party would like to upgrade their users to passkeys.

* A user visits the login page of the RP's website. They see a standard username and password form.

* Their user agent offers to AutoFill their saved username and password. The user accepts the suggestion.

* The RP checks the user's credentials and collects any nessesary information to register a credential.

* The RP makes a call to navigator.credentials.create with mediation = conditional.

* Because the user agent knows that it just mediated a authentication ceremony for the website and the user consents to credential creation, a passkey is created and the promised returned by `credentials.navigator.create` is fulfilled.

* The user now has both a password and a passkey saved for their account. The next time they visit the same log in page, they will be offered the passkey by AutoFill.

From the user's point of view, the experience is the same; they accept the first AutoFill suggestion to get logged in to their account.

## API

### Creation

To inform the user agent that it's desired for a credential to be created whenever an authentication ceremony was mediated via non-WebAuthn means.

```javascript
const registration = await navigator.credentials.create({
  mediation: 'conditional'
  publicKey: {
    challenge: ...,
    user: ...,
    rp: ...,
  },
});
```

The origin of the document where the authentication ceremony was mediated and the origin where `navigator.credentials.create` must be the same. 

## Privacy considerations

User agents must make users aware whenever a credential is created.

## Useful links

* Explainer: WebAuthn Conditional UI https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Conditional-UI
