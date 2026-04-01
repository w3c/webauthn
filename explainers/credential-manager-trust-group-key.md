# Explainer: Credential Manager Trust Group (CMTG) Key

Last Updated: 2025-10-15

## Objective

A WebAuthn extension enabling a credential manager to convey information to Relying Parties about the anti-phishing measures applied during credential manager sign-in.

## Background and motivation

Synced passkeys are available across different devices of a user, enabling secure sign-in on new and existing devices, provided the user has authenticated to a *credential manager* that manages these passkeys. This capability is crucial, as it allows websites to eventually eliminate phishable fallbacks for common sign-in scenarios, reserving them instead for higher-friction account recovery.

Consequently, the phishing protections implemented by a credential manager when a user adds a new device can directly impact the overall phishing protection offered by passkeys. For most websites, the limited number of credential managers, coupled with their strong security posture, is sufficient to consider passkeys a robust sign-in method, allowing them to, for instance, omit secondary measures like SMS OTPs.

One might suggest that credential managers must always require strong phishing protection, e.g. the use of hardware security keys. This would only mean passkeys don't sync at scale, and we are still stuck with common phishable fallbacks to support new device sign-ins. Therefore, credential managers must rely on other signals, and in some cases allow users to sign in to the sync fabric even when phishing cannot be strictly ruled out.

For some websites, this gap between their desired phishing resistance and credential manager sync policies means that passkeys sometimes need to be coupled with independent signals, such as step-up authentication with a separate factor.

At the same time, many credential managers do apply effective methods for detecting and ruling out phishing. Credential manager apps can often offer significantly better phishing protections than non-passkey based methods available to websites, e.g. ones based on physical proximity or integration with system APIs.

This proposal defines a WebAuthn extension that enables credential managers to indicate, in a privacy-preserving and ecosystem-friendly manner, when such phishing protections have been applied. Websites can then leverage this additional information to, for example, forgo step-up authentication or otherwise assign higher trust to the authenticating device.

## Phishing protections are about device relationships

Here *phishing* refers to compromises where a user inadvertently reveals their credentials to a remote attacker, who then uses those credentials to sign in to the legitimate website. Local credential harvesting, e.g. through malware, operates under different scaling laws and requires distinct defenses, thus falling outside the scope of this discussion.

To counter such remote attacks, the goal is typically to ensure that a trusted non-transferable factor is *locally* present during sign-in. However, this often presents a circular problem: the factor is typically another signed-in device, and its trustworthiness depends on what signals have been observed for that device. For example, a physical security key is only as trustworthy as the device that was used to register it.

It's tempting to think of phishing protection as an "assurance level" on the sign-in, i.e. where each sign-in is either phishing protected or not. If that were the case, a passkey assertion could simply indicate with a boolean that the credential manager sign-in was secure. There are a few problems with this.

- In the case of a phished credential manager account, we can't trust the phisher's device to report a boolean correctly.  
- Trust in a new device needs to be inherited from another device, which implies a bootstrapping problem: How does one trust the first device?  
- Evaluating the trustworthiness of devices in general is complex and RP-specific, and it is not viable to expand the scope of credential managers to a general device trust/integrity system.

To address the last two points, this proposal instead allows an RP to see when two devices with access to the synced passkey have a strong *non-remote relationship* in the eyes of the credential manager. The relationship is indicated by sharing a secret key between such related devices, thus addressing the first point.

Such a non-remote relationship strongly indicates that if the first device is trusted, i.e. believed to belong to the legitimate user, then the second device did not gain access to the credential manager through remote phishing. Relying parties can use this to carry trust annotations they establish on one device to the other.

We expect the exact way such relationships are established by credential managers to evolve over time. The FIDO Alliance may set guidelines on what is acceptable, but examples of relationships between devices A and B that would be in scope initially include:

1. Devices A and B were verified to be in proximity, e.g. with FIDO Cross-Device Authentication, during or after sign-in to the credential manager.  
2. Both devices were signed into the credential manager with the same physical FIDO Security Key.  
3. If devices A and B are both mobile phones, the credential manager has verified in a phishing-resistant way that their eSIMs are tied to the same phone number.

## Solution

To achieve this, participating credential managers offer a supplemental public key extension that can be requested on both create and get operations. When requested, the response will include a proof of possession of an additional passkey-specific secret key, that is only shared between devices with the strong, non-remote relationship described above, and its corresponding public key is included in the output. This public key is called the *credential manager trust group key*, or "CMTG Key" for short.

When a relying party observes an CMTG Key they have not seen before, it indicates that the credential manager does not know of any phishing-resistant signal between it and any other device that may have presented the same passkey before. In this case the RP may choose to trust the device based on other signals, or step the user up with additional challenges.

If the relying party has seen the same CMTG Key on a prior create or get call, it indicates that either the passkey is coming from the same device, or another device for which the credential manager has seen phishing-resistant signals linking it to the original device. This is a strong signal to the RP that trustworthiness of the original device can be considered when evaluating trust for the current device.

Relying parties request an CMTG key by requesting the `cmtgKey` extension on either a create or a get call:

```javascript
const cred = await navigator.credentials.get({
  publicKey: {
    challenge: ...,
    extensions: {
      cmtgKey: true  /* also works for .create */
    }
  }
});
```

The `credentialManagerTrustGroupKey` extension is an [authenticator extension](https://www.w3.org/TR/webauthn-3/#authenticator-extension), and will have two outputs:

1. The public key of the CMTG will be present in the [authenticator extension outputs](https://www.w3.org/TR/webauthn-3/#authenticator-extension-output).  
2. A signature proving possession of the CMTG private key will be In the [unsigned extension outputs](https://www.w3.org/TR/webauthn-3/#unsigned-extension-outputs).

CMTG Keys and their private keys are managed by credential managers, but only synced under this stricter criteria: CMTG private keys are only synced between devices with strong non-remote relationships.

Each CMTG Key is associated with a single passkey, i.e. the same CMTG Key is never shared between different passkeys, nor, consequently, between different relying parties. On the other hand, a single passkey may have multiple CMTG Keys associated with it. 

A credential manager that supports CMTG Keys will usually return one if requested. If no CMTG private key exists for the selected passkey on the current device, the credential manager will usually create a new one. A credential manager may not return a CMTG Key if e.g. it relies on the network to do so, and the network is down.

Note: Credential manager implementations may choose to create CMTG keys up front, but as from the perspective of relying parties, a good mental model is still that they are created on demand on new devices that don't have any strong relationships to other devices.

As the credential manager observes strong non-remote relationships between devices, it then transfers CMTG private keys between devices as appropriate. It is possible that a device ends up with multiple CMTG Keys for a given passkey. In this case, the authenticator will select one of them when CMTG Key is requested. The logic for that selection is left to credential managers, but in general they are expected to select a key in a consistent manner (i.e. not at random). For example, an implementation may choose to always select the oldest available CTMG Key that has been presented to the relying party before.

CMTG Keys are optional, i.e. RPs that don't need the additional signal can simply not request the CMTG Key extension, and there is nothing new to verify.

## Alternatives considered and questions

**Why doesn't the credential manager simply attest to the device trustedness?**  Device trustworthiness is a complex issue, and we think it is outside the scope of passkey credential managers (and possibly FIDO2/WebAuthn in general) to define the criteria for this. The decision depends on the business case of the relying party alone. Note that this doesn't preclude the use of alternative APIs for device trustedness as alternatives to, e.g., the common current practice SMS OTPs. If APIs or standards for such signals were to develop in the future, we'd expect they could be integrated in the guidelines for how CMTG Keys move between devices.

**This model only allows observing "related" or "not related" status between devices. Why do we not report the precise signal involved?**  We expect the signals and guidelines surrounding them to evolve over time. This proposal is addressed to the need of relying parties where passkeys fall *just* short due to the fact that credential managers need to balance access to passkeys with making them universal enough to replace phishable methods. We want to avoid the situation where such RPs are forced to analyze and bake in complex policies on the signals themselves and thus, having to keep those policies up to date with future advancements. We think this would ultimately lead to inconsistent and poor user experience and expectations.

For relying parties that need more fine grained or stricter signals, e.g. for compliance purposes, we think other more targeted APIs are a better option.

**Who sets the guidelines for admissible signals for determining non-remote relationships?**  This is left undecided in this proposal, but we expect a discussion in the relevant W3C WebAuthn and FIDO Alliance forums.
