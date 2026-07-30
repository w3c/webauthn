# Explainer: WebAuthn Get Client Capabilities

## Authors

Tim Cappalli (Okta) \<timcappalli@cloudauth.dev\>

_(with some help from Gemini)_

Last updated: 2025-04-29

## Summary

Currently, WebAuthn Relying Parties (RPs) have limited ways to determine certain WebAuthn client capabilities *before* initiating credential creation or authentication operations. This lack of upfront knowledge can lead to suboptimal user experiences, where RPs might offer interaction flows that the client (browser or underlying platform) cannot support, or conversely, fail to offer better experiences that *are* supported.

The `getClientCapabilities()` method provides a way for RPs to query the client about a defined set of capabilities, such as support for specific transport mechanisms (e.g., hybrid for cross-device authentication) or UI experiences (e.g., conditional mediation). It also provides a mechanism for clients to advertise support for specific WebAuthn extensions. This allows RPs to tailor their UI, authentication, and registration flows dynamically based on the client's current features, or gracefully fall back to other authentication methods.

## Goals

**Enable Dynamic User Experiences**: Allow RPs to adapt their login/registration UI based on known client capabilities before invoking create() or get(). For example, only showing a "Sign in with your phone" button if hybrid transport is supported and there is no local platform authenticator (think a kiosk or smart TV), or choosing between showing a “Sign in with a passkey” button vs. relying solely on autofill UI (conditional UI).

**Provide Standardized Capability Discovery**: Offer a reliable, spec-defined mechanism for feature detection, avoiding brittle User-Agent string parsing or speculative feature probing, and without adding individual static methods for each capability

**Inform Extension Usage**: Allow RPs to know if the client implements the client-side processing for a given WebAuthn extension before including that extension identifier in API calls.

## Non-Goals

**Discover Authenticator Capabilities**: This API reports on client (browser/platform) capabilities, not the capabilities of any specific authenticator that might be used during a ceremony. Authenticator capabilities are discovered during the create()/get() operations.

**Guarantee Feature Success**: Reporting true for a capability means the client supports it, but doesn't guarantee it will be successfully utilized in every specific create()/get() call (e.g., the user might cancel, or a specific authenticator chosen might lack a feature the client otherwise supports).

**Create a Broad Fingerprinting Surface**: The set of standardized capabilities reported should be limited to those with clear UX benefits, and clients have discretion over which capabilities (especially non-standard ones) they report (see Privacy & Security sections).

## General Use Cases

**General Passkey Support**: An RP needs to know whether passkeys are generally supported by the client before offering enrollment or sign in flows. For the most basic check, the RP calls `getClientCapabilities()` and looks for `passkeyPlatformAuthenticator` in the response. If the key is absent or reported as false, the RP may offer other authentication methods or skip passkey enrollment. This was previously accomplished by calling the static method `isUserVerifyingPlatformAuthenticatorAvailable()`.

**Cross-Device Flow Initiation:** An RP wants to offer a prominent "Sign in with your phone" button that initiates a hybrid (caBLE v2) flow. The RP calls `getClientCapabilities()`. If the result indicates support for hybrid transport (e.g., `{"hybrid": true}`), the RP displays the button. Otherwise, the RP might hide the button or offer an alternative flow.

**Conditional UI Optimization:** An RP prefers using Conditional Mediation (aka passkey autofill) for sign-in. The RP calls `getClientCapabilities()`. If the result indicates Conditional Mediation is *not* supported (e.g., `{"conditionalMediation": false}` or the key is absent), the RP can immediately display a traditional username input field or a “Sign in with a passkey” button instead of waiting for a potential autofill UI that will never appear.

**Extension-Specific UI/Logic:** An RP utilizes a specific WebAuthn extension (e.g., `prf`). Before initiating a `create()` or `get()` call that includes this extension, the RP calls `getClientCapabilities()`. If the result includes `{"extension:prf": true}`, the RP proceeds with including the extension; otherwise, it might fall back to a flow that doesn't require the extension or inform the user.

## Solution: The `getClientCapabilities()` method

```webidl
// In partial interface PublicKeyCredential
[SecureContext]
static Promise<PublicKeyCredentialClientCapabilities> getClientCapabilities();

// New typedef
typedef record<DOMString, boolean> PublicKeyCredentialClientCapabilities;

// Enum

enum ClientCapability {
    "conditionalCreate", // passkey upgrades
    "conditionalGet", // autofill UI
    "hybridTransport", // cross-device authentication
    "passkeyPlatformAuthenticator", // combo of isUVPAA() + hybridTransports
    "userVerifyingPlatformAuthenticator", // mirrors isUVPAA()
    "relatedOrigins", // Related Origin Requests
    "signalAllAcceptedCredentials", // Signal API capability
    "signalCurrentUserDetails", // Signal API capability
    "signalUnknownCredential" // Signal API capability
};
```

### Behavior

1. **Invocation:** An RP calls `PublicKeyCredential.getClientCapabilities()`.  
2. **Client Check:** The client (browser/platform) performs internal checks to determine the availability of a predefined set of WebAuthn capabilities and supported extensions. This process is platform-specific.  
3. **Return Value:** The method returns a `Promise` that resolves with a `PublicKeyCredentialClientCapabilities` object.  
4. **Structure:**  
   1. The keys of the record are `DOMString` values representing specific capabilities or extensions.  
   2. Keys representing standard capabilities (in `ClientCapability`) are simple strings (e.g., `"hybrid"`).  
   3. Keys representing client support for WebAuthn Extensions MUST be prefixed with `"extension:"` followed by the extension identifier (e.g., `"extension:credProps"`).  
   4. The keys in the returned record MUST be sorted in ascending lexicographical order.  
   5. The values are booleans:  
      * `true`: The client currently supports this capability or extension's client-side processing.  
      * `false`: The client currently does *not* support this capability or extension.  
5. **Key Omission:** If a capability or extension key is *not present* in the returned record, its availability is unknown or the client chooses not to disclose it. RPs should generally treat an omitted key as equivalent to `false` for the purpose of enabling UI that depends on it. Clients MAY omit keys for various reasons (e.g., privacy, experimental feature status).  
6. **Permissions Policy:** Invocation respects the `publickey-credentials-get` Permissions Policy. If the policy disallows usage in the current context, the promise MUST be rejected with a `DOMException` whose name is `"NotAllowedError"`.

## Detailed Design Discussion

* **Why Static?** The query is about the *client's* general capabilities, not tied to a specific credential instance. A static method fits this model best.  
* **Why Asynchronous?** Determining capabilities might require non-trivial platform-specific checks (e.g., querying OS services, checking hardware presence indirectly). An asynchronous Promise-based API prevents blocking the main thread.  
* **Why a Record/Dictionary?** This provides an extensible mechanism. New standard capabilities and extensions can be added over time without changing the method signature.  
* **Key Naming and Sorting:** Standard capability keys will be defined in the WebAuthn specification. The `extension:` prefix provides a clear namespace for extensions. Lexicographical sorting ensures consistent serialization and ordering, which can be helpful for testing and potentially for caching mechanisms, though caching is not mandated here.  
* **Client Discretion (Key Omission):** Allowing clients to omit keys is crucial for privacy (see below) and allows flexibility. For instance, a browser might choose not to report an experimental capability or one deemed too revealing in certain contexts.  
* **Extension Reporting:** Reporting `{"extension:foo": true}` only indicates the *client* implements the necessary processing for the "foo" extension. It does *not* guarantee that any *authenticator* used subsequently will also support "foo". RPs must still handle cases where an extension is requested but not acted upon by the authenticator.

## Security Considerations

* **Fingerprinting Surface:** Exposing client capabilities increases the potential fingerprinting surface area of the browser/platform.  
  * **Mitigation 1 (Limited Standard Keys):** The WebAuthn WG carefully curated the set of *standard* capabilities exposed, focusing on those with strong justifications for improving user experience that outweigh the fingerprinting risk.  
  * **Mitigation 2 (Client Discretion):** The specification explicitly allows clients to *omit* keys from the result. Browsers can use this discretion to avoid revealing capabilities deemed too identifying, experimental, or sensitive in certain contexts.  
  * **Mitigation 3 (Permissions Policy):** The feature is gated by the existing `publickey-credentials-get` Permissions Policy, meaning it requires a Secure Context and can be disabled by site owners or potentially via user browser settings, similar to the core `get()` operation.  
* **Information Disclosure:** The revealed capabilities (e.g., hybrid support, conditional UI support) are generally related to browser/platform features rather than sensitive user data or specific authenticator details. The direct security risk from knowing these capabilities is considered very low.

## Privacy Considerations

* **Fingerprinting:** This is the primary privacy concern, overlapping significantly with security considerations. The same mitigations apply: limiting standard keys, allowing client omission, and gating via Permissions Policy.  
* **Minimization:** Clients should aim to report the minimum set of capabilities necessary. The ability to omit keys supports this principle. The standard set should be minimal.  
* **Transparency:** It should be clear to developers which capabilities *might* be reported. Browser developer tools could potentially surface the results of this call for inspection.

## Stakeholder Feedback / Interest

* **RP Developers:** This capability came from direct developer and UX designer feedback  
* **Browser Vendors:** Two browser engines have implemented the method

## Alternatives Considered

1. **User-Agent String Parsing:** Highly discouraged. UA strings are unreliable, change frequently, are being frozen/reduced for privacy reasons, and often don't accurately reflect specific WebAuthn feature availability tied to underlying OS services or runtime flags.  
2. **Attempt Operation and Handle Failure:** RPs can try to initiate a flow (e.g., conditional UI `get()`, or `create()` with hybrid options) and handle errors if the client doesn't support it. This leads to poor UX (e.g., "flickering" UI, confusing error messages, unnecessary user steps) which `getClientCapabilities()` aims to prevent.  
3. **Expanding Existing Static Methods:** Could potentially add flags or options to `isUVPAA()` or `isCMA()`. This was deemed less clean and less extensible than a dedicated method returning a dictionary, especially for reporting extension support and future capabilities.  
4. **No Action:** Maintain the status quo, forcing RPs to use suboptimal approaches (UA sniffing, degraded UX).

## Accessibility Considerations (A11y)

This API has no direct impact on accessibility rendering itself. However, it can *indirectly improve* accessibility by enabling RPs to:

* **Present Clearer Choices:** By knowing capabilities upfront, RPs can avoid presenting confusing or non-functional UI elements to users. For example, not showing a greyed-out or error-prone "Sign in with phone" button if hybrid is unavailable improves clarity for all users, including those using assistive technologies.  
* **Optimize Flow:** Avoiding unnecessary steps (like waiting for a conditional UI prompt that never comes) can make the authentication process smoother and less confusing.

The RP remains responsible for ensuring the UI it *does* render based on these capabilities is accessible.
