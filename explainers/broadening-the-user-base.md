# Explainer: Broadening the User Base of WebAuthn

Discussion issue and more detailed roadmap: https://github.com/w3c/webauthn/issues/1637<br>
Author: agl

## Introduction

Federated sign-in has been around for a long while, but passwords remain the most common method of authentication on the web. Passwords have many benefits but also many, well known, costs. Users would be better off with if there was an alternative that was *dependable* (always backed up and thus survives device loss), *safe* (requires biometrics to exercise; can’t be phished), and *less hassle* (no need to care about whatever password database leaked this month).

Passwords are a problem for websites too. They want an answer that speeds sign-ins, reduce account compromises, reduces expensive forgot-password support calls, and removes the risk of having to store passwords securely.

WebAuthn is the Web standard that supports security keys: often physical USB tokens used as a 2nd factor for authentication. WebAuthn already supports being the only factor: browsers can display a list of accounts from a security key and the security key can collect a local PIN or biometric to verify that the correct person is present. But it seems unlikely that broad numbers of people are going to purchase a pair of security keys to use WebAuthn, and manage double-registering on all their sites.

Thus, in WebAuthn L3, the WG is considering several changes to make WebAuthn more broadly applicable as a password replacement.

## Possible experiences in a future WebAuthn

In order to motivate discussions about what WebAuthn changes may be needed to support wider adoption we would like to sketch some user experiences that we might want to enable:

When signing up on a new website, rather than being forced to choose a password, a user is invited to register a WebAuthn authenticator. They choose to register their phone as browsers will support using phones as security keys (Chrome already does). This creates a discoverable credential on the phone and that credential is encrypted and synced so that loss of the phone doesn’t lock the user out.

Later, that same person picks up their phone and goes to the website of that service. The autocomplete UI in the browser offers the discoverable credential as a sign-in option, which can be exercised by using the biometric sensors on the phone. If the user installs the service’s app on their phone then the credential will also be available to facilitate sign-in there.

When signing in on a different computer, either the credential will already be locally present (if the computer is using the same sync fabric as the phone) and suggested by autocomplete, or else the user’s phone can be used to transmit the assertion to the computer. In the latter case, the service may invite the user to enroll a local [platform authenticator](https://w3c.github.io/webauthn/#platform-authenticators) for easier sign-in in the future. (Now the newly registered credential may be part of a different sync fabric, and thus enable local sign-in on other devices.)

When signing into existing services using a username+password, those services can offer to enroll a WebAuthn credential and, ultimately, delete the user’s password. For such users, we would expect a significant reduction in account recoveries as synced credentials solve many issues that previously required site-specific recovery flows.

Very roughly, phones become roaming authenticators capable of creating “durable” credentials: ones which can survive loss of the device. Within an ecosystem of devices, credentials may be synced between devices but there is also support for sending signatures between devices and thus between ecosystems.

In this world, physical security keys continue to serve important uses as there exist many contexts where syncable credentials on phones do not meet regulatory-, compliance-, or security-related needs. If we can grow the ecosystem of WebAuthn-enabled services with an experience like this then we hope for the use of physical security keys to grow too, although we do not expect the typical consumer user to have them.

## Web Platform changes

Much of the work to enable the flows suggested above happens &ldquo;above&rdquo; the Web Platform. For example, WebAuthn defines an API for sites to use authenticators, but it's browsers that wire it up such that FIDO USB keys, or phones, implement the authenticator interface and can be used.

But there are several changes to the Web Platform that would be critical to making a coherent solution.

### Conditional UI

Sites are going to start with a user population that probably all use passwords. WebAuthn calls currently trigger modal UI that expects that a user knows what to do, but that's far too abrupt for a transition from passwords. Thus we suggest that an existing field of the CredMan spec be used to allow sites to request a more subtle UI that accommodates users who might not have WebAuthn credentials. As a browser, we expect to integrate that with our auto-complete system.

This has its [own issue](https://github.com/w3c/webauthn/pull/1576) and a [separate explainer](https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Conditional-UI). A separate TAG review request will be filed for the CredMan changes involved in this.

*Alternatives*: several sites have requested a silent API to learn whether the current user is known to have WebAuthn credentials or not. However, this solution would change the privacy model of WebAuthn. An eariler draft of the idea had a non-modal pop-up appear at the top of the browser window, but this offers fewer opportunities for integration with other sign-in methods and wasn't gated behind a user gesture.

### Assertion attachment

(Merged in https://github.com/w3c/webauthn/pull/1668)

In order for a site to know whether a local platform authenticator was used, or whether the user used another device and thus might want to register a local platform authenticator, we propose that an attachment field be added to assertion responses. This discloses whether the authenticator used to sign-in was built into the device (&ldquo;platform&rdquo;) or something like a USB security key or phone (&ldquo;cross-platform&rdquo;). 

Thus, if the attachment field of the assertion is not “platform”, and [isUVPAA](https://w3c.github.io/webauthn/#sctn-isUserVerifyingPlatformAuthenticatorAvailable) returns true, then sites may offer to the user to register the current device's platform authenticator.

*Alternatives*: originally the authenticator transport (e.g. &ldquo;usb&rdquo;) was going to be provided. After discussions in the WG we concluded that the attachment sufficies.

### Preventing unintended credential overwrites on [platform authenticators](https://w3c.github.io/webauthn/#platform-authenticators)

A given authenticator only stores a single discoverable credential for a given (RP ID, user ID) pair. Some authenticators always create discoverable credentials. This can lead to a situation where a platform credential is unexpectedly overwritten by a second registration on the same platform.

This is a long-standing issue with WebAuthn. Sites can already provide a list of currently known credentials in a WebAuthn create() call and we propose a clarification to the spec that suggests that browsers not show a user-visible error when an existing credential is found but rather gather user consent as-if the request was being fulfilled. This way a site either gets a new credential (if there was no collision) or learns that the a credential already existed, which serves their needs.

### Device-key extension

WebAuthn, until now, had an informal expectation that credentials were hardware-bound. As a measure to potentially address some of the challenges of introducing syncable credentials we have floated the idea that syncable credentials may be paired with an automatically-generated, device-bound key pair. This would be a WebAuthn extension and is being developed in https://github.com/w3c/webauthn/pull/1663.

### Durable signal

Status: speculative; we’re not sure about this.

If we are suggesting to sites that passwords could be deleted once WebAuthn is used, then it’s important for them to know whether a credential is “durable” (i.e. backed up) or whether it disappears with device loss. Registering a single durable credential may be a strong enough signal to offer to delete the user’s password, but perhaps several non-durable credentials are needed.

Without such a signal sites may conservatively keep the password path for nearly everyone, and passwords will turn into an obscure backdoor that people leave unattended. Thus we have wondered about defining authenticator data flag bit 3 to be: 0 = lost upon device loss, 1 = durable (i.e. synced).

(This could be an extension, but we have these bits to use and, if we ever get to the last bit, we can just define an “extended flags” extension at that time.)

Since it’s in the authenticator data, this information is also provided with every assertion. Thus a credential can become durable at a later date. A phone, for example, may not want to initially set the durable flag during registration if it hasn’t successfully uploaded the encrypted credential at that point.

(Physical security keys could also adopt this if they offered a mechanism for backing up credentials.)

### Report signaling

Status: speculative; we’re not sure about this at all.

If a credential is deleted on a site, it will not be automatically deleted on the corresponding authenticator. Also, if a site attempts to overwrite a credential with a create() call, there’s a risk that the new credential will not reach the server and the user will be locked out.

Thus we have some ideas around an augmentation of CredMan that allows signals about credentials to be asynchronously asserted to the browser by a site:

navigator.credentials.report() would take the following:

```
dictionary CredentialReportOptions {
  DOMString signal;  // “deleted”, “rejected”, or “accepted”.
};
```

That dictionary would be merged with type-specific members, as the other CredMan options dicts are, so that a call like the following would work:
```
navigator.credentials.report({
  signal: “accepted”,
  publicKey: {
    id: credentialId,
  },
})
```

The signals would mean:

deleted: that the given credential ID has been deleted by the user. This should promptly follow the user taking some action on the site to delete the credential. Perhaps if the browser knows that it’s a local credential the user might be asked if they wish to delete it locally. (But the site does not learn what happened. Perhaps the browser did nothing.)

rejected: the site rejected the assertion for the given credential ID. This should promptly follow such an assertion being provided by the browser. If that credential recently overwrote another, perhaps that should be reverted. If not, perhaps the user should delete that credential because it is no longer recognised by the server.

accepted: this site accepted the assertion for the given credential ID. This should promptly follow such an assertion being provided by the browser. If older versions of that credential were being kept around because the platform didn’t know if an overwrite reached the server, then they could be released.
