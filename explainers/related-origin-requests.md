# Explainer: Related Origin Requests

> [!IMPORTANT]  
> This document is no longer maintained. 
>
> For details about Related Origin Requests, please visit https://passkeys.dev/docs/advanced/related-origins/.

## Background

All WebAuthn credentials are associated with a single [Relying Party ID](https://www.w3.org/TR/webauthn-2/#rp-id) (“RP ID”), which is essentially a domain name, and all WebAuthn requests are processed in the context of an RP ID. An origin can use any RP ID formed by discarding zero or more labels from the left of its [effective domain](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain) until it hits an [effective TLD](https://en.wikipedia.org/wiki/Public_Suffix_List). So `www.example.com` can use the RP IDs `www.example.com` or `example.com`. But not `com`, because that’s an eTLD.

The RP ID mechanism separates credentials for different sites so that a credential cannot be used as a single, global credential for authenticating everywhere.

RP IDs are _not_ WebAuthn’s anti-phishing protection. Traditional phishing is prevented by including the origin of the request in the [CollectedClientData](https://www.w3.org/TR/webauthn-2/#dictionary-client-data), where the relying party can check it and reject requests from unknown origins. Rather RP IDs should be thought of as a limitation on web sites, not a protection for them. (But extensions to WebAuthn, such as [`prf`](https://w3c.github.io/webauthn/#prf-extension) and [`largeBlob`](https://w3c.github.io/webauthn/#sctn-large-blob-extension) add an assumption that asserting a credential is a somewhat private operation, muddying that perspective.)

## Problems with RP IDs

This RP ID system has existed since WebAuthn level one, but creates a number of challenges:

### Sites with many eTLDs

Several sites have many country-specific domains, e.g. `example.com`, `example.de`, `example.in`, … These domains will share an account database and so users can enter passwords on any of them to get signed in. Most password managers have mechanisms for understanding that these are all effectively the same site and will fill passwords across them. However, WebAuthn has a notably worse experience in this case because the different domains imply different RP IDs and thus credentials cannot be used across them.

### Brands that span or change domains

Some brands have chosen for marketing reasons to span domains, e.g. `acme.com` and `acmerewards.com`. Sometimes this pattern results from business acquisitions and, in other cases, companies have renamed themselves. Similar to the previous case, by sharing an account database on the backend passwords can work in these situations reasonably well, but WebAuthn is inflexible and requires that users re-register with each domain separately.

### Mobile apps without a domain

WebAuthn is mirrored into mobile APIs so that credentials can work across platforms. Many apps use service providers to handle various backend tasks including authentication. In the case of passwords, those service providers can allow their customers to export their password database and so move between different service providers, or take over the work themselves. However, with WebAuthn the service provider has to bind all credentials to an RP ID and thus to a domain. But not all mobile apps _have_ a domain name and thus a default RP ID would be a domain under the service provider's control, locking the app into that provider.

## Proposal

The best current option for sites with these issues is to use redirects and iframes to centralise the use of WebAuthn on a single domain. But the feedback is clear that this is a major impediment to adoption and also that these solutions may (or do) run afoul of privacy controls that browsers are implementing. Thus we seek to build a more explicit solution.

Thus we propose a [well-known URL](https://www.rfc-editor.org/rfc/rfc5785.html) where an origin can list other origins that are authorized to use it as an RP ID. The URL is `https://{RP ID}/.well-known/webauthn`. It must be served with [content type](https://datatracker.ietf.org/doc/html/rfc9110#name-content-type) of `application/json`, using HTTPS, and contain a single [JSON](https://datatracker.ietf.org/doc/html/rfc8259) object. For example:

```json
{
    "origins": [
        "https://example.co.uk",
        "https://example.de",
        "https://example-rewards.com"
    ]
}
```

The processing of WebAuthn requests would be altered so that, when processing the RP ID parameter [during credential creation](https://www.w3.org/TR/webauthn-2/#CreateCred-DetermineRpId) or [during credential assertion](https://www.w3.org/TR/webauthn-2/#GetAssn-DetermineRpId), before returning a [SecurityError](https://webidl.spec.whatwg.org/#securityerror), the user agents fetches the URL specified above (without credentials and without referrer) and performs the following processing given the requested RP ID, _rpIdRequested_:

1. If the fetch fails, does not have a content type of `application/json`, or does not have a status code (after following redirects) of 200, then return a SecurityError.
2. If the body of the resource is not a valid JSON object then return a SecurityError.
3. If the value of the _origins_ member of the JSON object is missing, or is not a list of strings, return a SecurityError.
4. Let _labelsSeen_ be an empty set.
5. For each string in _origins_:
    1. Let _url_ be the result of parsing the string as a URL. If that fails, continue with the next element of the list.
    2. Let _domain_ be the [effective domain](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain) of _url_. If that is null, continue with the next element of the list.
    3. Remove any [public suffix](https://url.spec.whatwg.org/#host-public-suffix) from the end of _domain_, including private registries and unknown registries. If _domain_ is now empty, continue with the next element of the list.
    4. Split _domain_ into [labels](https://datatracker.ietf.org/doc/html/rfc1034#section-3.1) and let _label_ be the right-most one.
    5. If _label_ is not in _labelsSeen_ then:
        1. If the number of elements in _labelsSeen_ is less than _maxLabels_ then insert _label_ into _labelsSeen_.
        2. Otherwise, continue with the next element of the list.
    6. If _rpIdRequested_ and _url_ are [same origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin) then stop this processing and allow the WebAuthn request to continue, using _rpIdRequested_.

These processing steps seek to limit the number of different domains that can be authorised while still meeting the goals above. Each element of the list is processed to extract the eTLD + 1 label. For example, the eTLD + 1 labels of `example.co.uk` and `example.de` are both `example`. But the eTLD + 1 label of `example-rewards.com` is `example-rewards`.

The limit, _maxLabels_, is applied to the number of different eTLD + 1 labels so that sites with many eTLDs can use this mechanism while a tighter limit can be applied to the number of more distinct domains that can be used.

The processing is incremental so that an innocuous-looking change—adding an extra element to the list—doesn’t suddenly cause the list to be invalid and break all existing sites. Only the excessive element(s) will be ignored.

The proposed value of _maxLabels_ is five.

## Similar systems

Both Android and iOS have very similar systems for allowing mobile apps to use RP IDs: [digital asset links](https://developer.android.com/training/sign-in/passkeys#add-support-dal) and [#associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains), respectively, which both use JSON files in the `.well-known` directory.  (Neither of these systems have any documented limits on the number of apps that can use an RP ID.)

Solutions for sharing _passwords_ between websites vary between password managers. The digital asset links system [can also be used](https://developers.google.com/identity/smartlock-passwords/android/associate-apps-and-sites) for this by Google Password Manager. Safari has [a different system](https://github.com/apple/password-manager-resources#shared-credentials).

[Secure Payment Confirmation](https://www.w3.org/TR/secure-payment-confirmation/) allows WebAuthn credentials to be used from any origin, with a payment-focused UI, provided that SPC was explicitly enabled for the credential at creation time.

WebAuthn also has support for making assertions [within iframes](https://www.w3.org/TR/webauthn-2/#sctn-iframe-guidance), which can operate across domains.

## Communication with the user

While the details of user-agent UI are out of scope for the WebAuthn specification, they are still  important.

We imagine moving away from the RP ID as a user-visible concept where possible and instead communicating where a given credential has been used. Anchoring user communication on a single identifier, like the RP ID, is already running into limitations because of mobile apps:

Consider the possible UI when a mobile app makes a WebAuthn request. The app has to specify an RP ID and that RP ID is validated in ways specific to the mobile platform. The UI could choose to show the RP ID but that RP ID might be confusingly unrelated to the mobile app. (If the mobile app is using a service provider for backend authentication services then the RP ID might be something very unfriendly like `app1234.serviceprovider.com`.) However, if the UI only shows the name of the app then users will be unaware when multiple apps are using the same RP ID behind the scenes.

It would hopefully be clearer to be explicit about the other apps and sites where a credential has been used.

Not all authenticators will support storing the list of apps and sites for each credential, and shifting UIs takes time. In the shorter term, when a credential is used across domains, we imagine communicating to the user both the origin where the credential is being used, and the RP ID that it was registered on, when this proposal is in use.

## Evaluation

Considering the initial motivations:

* The problem of sites with many eTLDs is solved.
* The problem of brands that span or change domains is solved on a small scale. The _maxLabels_ limitation imposes a limitation on the number of brands that can be handled in this way. It’s possible that the proposed value of _maxLabels_ is too small, but we seek feedback on that point.
* The problem of mobile apps without a domain is somewhat ameliorated. Purchasing a domain remains the best solution and this proposal may make picking the specific name less of a commitment. This proposal makes it possible for a mobile app to add a website without needing to host a page on a service provider’s origin as long as the service provider will host a well-known file.

## Alternatives considered

We considered both RP UUIDs and RP Keys, where the former are RP IDs that are random values with no access controls, and the latter has RP IDs be the hash of a public key where access control is implemented with signed authorisations.

We worry about the complexity and UI impact of both of these. RP UUIDs would allow any site to create (and overwrite) credentials for any RP UUID. They would also allow any site to assert any credential with an RP UUID, making some extensions to WebAuthn, such as [`prf`](https://w3c.github.io/webauthn/#prf-extension) and [`largeBlob`](https://w3c.github.io/webauthn/#sctn-large-blob-extension), unusable.

RP Keys would be a lot of complexity and assume that sites are able to keep a private key over the long term.

Both of these proposals would better address the needs of mobile apps, but on a cost–benefit basis, a .well-known achieves most of the benefit at far less cost.
