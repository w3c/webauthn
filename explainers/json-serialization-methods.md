# WebAuthn JSON Serialization Methods Explainer

**Author:** Martin Kreichgauer \<martinkr@google.com\>

**Last update:** Dec 14, 2022

## Motivation

Users of the WebAuthn API call navigator.credentials.create() and navigator.credentials.get() to register and challenge credentials stored on an authenticator such as a security key. Various request and response parameters for these operations are binary-valued, for example the [PublicKeyCredentialCreationOptions.challenge](https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-challenge) BufferSource or the [AuthenticatorAttestationResponse.attestationObject](https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject;) ArrayBuffer. 

The values of these fields are usually processed server-side. For example, the server generates the challenge passed into PublicKeyCredentialCredentialOptions, and decodes a signature over said challenge from the attestationObject in order to verify it. Because JSON.parse() and JSON.serialize() do not serialize data from these binary-valued fields, WebAuthn developers need to provide their own logic for passing serialized representations of WebAuthn request and response objects between a client and server. 

Not being able to pass WebAuthn types between a client and server easily and out of the box has frequently been named by developers as one of the pain points in using API. We therefore would like to provide methods for deserializing request objects from and serializing response objects to JSON.

## Proposal

The basic idea is to convert the relevant request types from, and the PublicKeyCredential response type to JSON objects. The JSON objects mirror their “regular” counterparts in IDL, but have all ArrayBuffer- or BufferSource-valued fields replaced with Base64URL-encoded strings of the binary data. (For historical reasons, the WebAuthn API uses Base64URL instead of regular Base64 for encoding binary data to strings; [example](https://w3c.github.io/webauthn/#dom-collectedclientdata-challenge).)

More concretely, this adds the following methods:

 *  [PublicKeyCredential.parseCreationOptionsFromJSON()](https://w3c.github.io/webauthn/#sctn-parseCreationOptionsFromJSON) (static method):
This returns an instance of PublicKeyCredentialCreationOptions parsed from PublicKeyCredentialCreationOptionsJSON.
 *  [PublicKeyCredential.parseRequestOptionsFromJSON()](https://w3c.github.io/webauthn/#sctn-parseRequestOptionsFromJSON)  (static method): This returns an instance of PublicKeyCredentialRequestOptions parsed from PublicKeyCredentialRequestOptionsJSON.
 *  [PublicKeyCredential.toJSON()](https://w3c.github.io/webauthn/#dom-publickeycredential-tojson) (instance method): This adds the [toJSON() regular operation](https://webidl.spec.whatwg.org/#idl-tojson-operation) to the PublicKeyCredential interface type. Depending on which operation created the PublicKeyCredential instance, toJSON() it returns either a RegistrationResponseJSON or an AuthenticationResponseJSON.
