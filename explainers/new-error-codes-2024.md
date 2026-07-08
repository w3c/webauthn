# Explainer: New Error Codes (2024)

**Author:** Matthew Miller <[mattmil3@cisco.com](mailto:mattmil3@cisco.com)>

**Last update:** July 15, 2023

## Summary

Introducing more nuanced error codes to WebAuthn helps Relying Parties better understand a user's passkeys experience.

## Background

Relying parties generally lack insights into a user's interaction with the user agent when the user is completing a WebAuthn ceremony. In the majority of cases of a ceremony ending unsuccessfully, the RP receives a `NotAllowedError` and little explanation as to **why** the user was unsuccessful. Did the user simply cancel out? Did the ceremony time out? Did the user try to register something that didn't support user verification? Was it because the embedded webview in the native app lacked insufficient platform-level permissions to handle WebAuthn? Neither by error name nor by error message is the RP able to reliably understand whether the user might succeed if they try again, or if successful WebAuthn use is impossible.

There is a strong desire from large RPs to be able to better understand their users' interactions with WebAuthn. Enabling RPs to measure and improve their passkeys UX will lead to better passkeys experiences that users will want to engage with. Relying Parties that want to offer better user remediation guidance will become more empowered to do so as well.

Introducing more nuanced error codes can be done in a way that gives RPs meaningful data points to achieve these goals without impinging on a user's privacy.

## Example use cases

### `UserCancellationError`

Absolutely nothing went wrong, the user simply decided they didn't want to register a passkey right now. A new `UserCancellationError` helps the RP understand this nuance over the current `NotAllowedError` that could mean a number of possible other issues arose.

### `HybridPrerequisitesError`

The browser wanted to prompt the user to try for a hybrid authentication, but found that it lacked OS-level permission to use Bluetooth. After notifying the user of this, the user cancels the ceremony. The browser raises a `HybridPrerequisitesError` error, which the Relying Party detects and shows the user how to grant the browser Bluetooth permission. The user is able to turn on Bluetooth on their own and then successfully complete auth.

### `UserHybridCancellationError`

An RP has a registration flow that specifies `authenticatorAttachment: "cross-platform"` in the options passed to `.create()`. Analytics currently sees a lot of `NotAllowedError` failures and low adoption of this flow; the RP is unsure why users aren't going for it. The introduction of a new `UserHybridCancellationError`, though, helps the RP to understand that users are getting confused when they are shown the hybrid QR code. The RP tweaks its UX to help prime future users to make sense of what they're seeing, and the hybrid flow starts seeing more adoption.

### `UserVerificationError`

A user comes back from vacation and finds they've forgotten their security key PIN. The `NotAllowedError` previously raised from canceling the auth attempt now raises a `UserVerificationError`. Helpdesk sees this user often generate this error, so they preemptively reach out to help the user reset and re-register their security key.

### `TimeoutError`

A user triggers a page navigation to a page that immediately calls WebAuthn. The page takes a bit too long to load, though, so the user leaves their desk to go refill their coffee. A short hallway conversation later and the ceremony times out. The RP sees a new `TimeoutError` instead of a `NotAllowedError` get raised from the call to `.get()`. This new error helps the RP feel confident that nothing actually went wrong. The user is shown more succinct UI encouraging them to simply try the ceremony again.

## API

No changes are being proposed to the overall invocation of WebAuthn. These new error codes involve changes in user agent behavior when rejecting the Promises from calls to `.create()` and `.get()`, which RP's are typically already set up to handle.

## Privacy considerations

Emphasis is being placed on the need for a user to interact with the ceremony in some meaningful way so as to communicate a desire to successfully complete registration or authentication. There is no desire from this effort to introduce new error codes that would become a way to understand e.g. the user has no credentials for the site.

## Useful links

- GitHub Issue: https://github.com/w3c/webauthn/issues/2096
- GitHub PR: https://github.com/w3c/webauthn/pull/2095
