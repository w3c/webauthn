# WebAuthn Remote Desktop Support Explainer

**Author:** [Martin Kreichgauer](mailto:martinkr@google.com)  
**Published:** April 6, 2022

## Motivation

The Web Authentication API (WebAuthn) mediates website access to public key credentials stored on an authenticator for the purpose of building phishing-resistant authentication experiences. WebAuthn credentials are bound to a domain, called the Relying Party ID (RP ID). Websites can exercise WebAuthn credentials if the RP ID is a registrable suffix of their origin's domain.

Remote desktop web applications let users interact with the (native) desktop environment of a remote host from a local client (web) application.

A user may want to use a WebAuthn authenticator connected to their local client in order to sign into a website in a browser running on a remote host. But users typically cannot physically access the remote desktop host, so it's impossible for them to plug in a USB security key or to pass the biometric challenge of a built-in platform authenticator. Instead, we propose a model for web-based remote desktop clients to execute remote WebAuthn requests locally.

## Proposal

We assume the remote desktop software is somehow able to intercept the WebAuthn request occurring on the remote host browser and forward that request to the local client web app. We would like the remote desktop client to be able to execute the forwarded WebAuthn request locally on behalf of the original Relying Party's origin. 

To achieve this, the remote desktop client would invoke the WebAuthn API with the same PublicKeyRequestOptions dictionary as the original host, but add an additional extension that indicates it wants to act on behalf of the remote caller origin.

```
// The remote desktop client (https://myrdc.example) calls WebAuthn with
// the PublicKeyRequestOptions of the original request issued by
// https://accounts.example.com and forwarded from the remote desktop host.
navigator.credentials.get({publicKey: {
    challenge: …,
    // Note that https://myrdc.example can't regularly claim this RP ID.
    rpId: 'example.com',
    allowCredentials: { … },
    extensions: {
        …,
        // Additional extension inserted by https://myrdc.example to act on 
        // behalf of https://accounts.example.com.
        remoteDesktopClientOverride: {
            origin: 'https://accounts.example.com',
            sameOriginWithAncestor: false,
        },
    },
}});
```

The two extension members, `origin` and `sameOriginWithAncestors`, replace the arguments of the same names when invoking [`PublicKeyCredential`'s `[[[DiscoverFromExternalSource]]` internal method](https://w3c.github.io/webauthn/#dom-publickeycredential-discoverfromexternalsource-slot). This causes the user agent to match the scope of the RP ID against the overridden origin (https://accounts.example.com), rather than the origin of the Relying Party (https://myrdc.example). The supplied values are also used to assemble the [`CollectedClientData` dictionary](https://w3c.github.io/webauthn/#dictionary-client-data) that the authenticator signs over when generating an assertion. (The remaining `CollectedClientData` members can be inferred from context and therefore don't need to be injected.) To the Relying Party, the response should be indistinguishable from one that would have been generated without forwarding.

Extension processing would be analogous for WebAuthn create() calls: Presence of the extension causes the equivalent arguments to the [`[[Create]]` internal method](https://w3c.github.io/webauthn/#sctn-createCredential) to be overridden, such that the request is processed as if it had been made by the Relying Party origin on the remote host.

## Security Considerations

By design, this extension breaks the WebAuthn security model that guarantees non-phishability of the credentials. Implementing user agents would need to restrict the ability to exercise this functionality to trusted remote desktop applications. If an unauthorized origin attempts to use the extension, the user agent returns a "SecurityError" `DOMException` immediately. We are currently exploring suitable mechanisms for letting enterprises enable this capability for individual remote desktop applications for their managed environments.

## Non-Goals

-  Specify how to intercept requests on the remote host. (This could for example be realized with a browser extension API. However, this explainer focuses on the capabilities necessary for the local client web app only.)
-  Propose a solution for remote desktop clients that run as native apps. (E.g. Windows Remote Desktop Services may support redirection of WebAuthn requests based on forwarding raw device access.) 
-  Allow access to WebAuthn credentials on behalf of other Relying Parties/sites in contexts other than remote desktop software (e.g. sharing credentials between two related sites hosted on origins that don't share an eTLD+1).
