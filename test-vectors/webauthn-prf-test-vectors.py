#!/usr/bin/env python3

from cryptography.hazmat.primitives import ciphers, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fido2 import cbor
from fido2.utils import sha256


def prng(seed, i):
    return sha256(seed + bytes([i]))

def hmac_sha256(key, message):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()

def hkdf_sha256(salt, ikm, L, info):
    return HKDF(algorithm=hashes.SHA256(), length=L, salt=salt, info=info).derive(ikm)


class PinProtocolV1:
    def ecdh(self, privateKey, peerPublicKey):
        Z = privateKey.exchange(ec.ECDH(), peerPublicKey)
        return self.kdf(Z)

    def kdf(self, Z):
        return sha256(Z)

    def encapsulate(self, privateKey, peerPublicKey):
        return privateKey.public_key(), self.ecdh(privateKey, peerPublicKey)

    def decapsulate(self, privateKey, peerPublicKey):
        return self.ecdh(privateKey, peerPublicKey)

    def encrypt(self, key, demPlaintext, iv):
        k = key
        iv = bytes([0] * 16)
        c = ciphers.Cipher(ciphers.algorithms.AES256(k), ciphers.modes.CBC(iv)).encryptor()
        return (c.update(demPlaintext) + c.finalize())

    def decrypt(self, key, ciphertext):
        k = key
        iv = bytes([0] * 16)
        ct = ciphertext
        c = ciphers.Cipher(ciphers.algorithms.AES256(k), ciphers.modes.CBC(iv)).decryptor()
        return c.update(ct) + c.finalize()


class PinProtocolV2(PinProtocolV1):
    def encrypt(self, key, demPlaintext, iv):
        k = key[32:]
        c = ciphers.Cipher(ciphers.algorithms.AES256(k), ciphers.modes.CBC(iv)).encryptor()
        return iv + (c.update(demPlaintext) + c.finalize())

    def decrypt(self, key, ciphertext):
        k = key[32:]
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        c = ciphers.Cipher(ciphers.algorithms.AES256(k), ciphers.modes.CBC(iv)).decryptor()
        return c.update(ct) + c.finalize()

    def kdf(self, Z):
        return (hkdf_sha256(salt=bytes([0] * 32), ikm=Z, L=32, info=b'CTAP2 HMAC key')
                + hkdf_sha256(salt=bytes([0] * 32), ikm=Z, L=32, info=b'CTAP2 AES key'))


def tohex(b):
    if isinstance(b, int):
        return tohex(bytes([b]))
    else:
        return b.hex() if b is not None else "DELETE"


def setup_test_vectors(seed, plat_prik_idx, authnr_prik_idx, cred_random_idx):
    plat_prik_raw = prng(seed, plat_prik_idx)
    authnr_prik_raw = prng(seed, authnr_prik_idx)
    authnr_prik = ec.derive_private_key(int.from_bytes(authnr_prik_raw, 'big'), ec.SECP256R1())
    plat_prik = ec.derive_private_key(int.from_bytes(plat_prik_raw, 'big'), ec.SECP256R1())
    authnr_pub_raw = authnr_prik.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    cred_random = prng(seed, cred_random_idx)

    print(f"""#### CTAP2 `hmac-secret` extension #### {{#test-vectors-extensions-prf-ctap}}

The following examples may be used to test [=[WAC]=] implementations
of how the [=prf=] extension uses the [[FIDO-CTAP]] `hmac-secret` extension.
The examples are given in CDDL [[RFC8610]] notation.
The examples are not exhaustive.

- The following shared definitions are used in all subsequent examples:

    <xmp class="example" highlight="cddl">
    ; Given input parameters:
    platform_key_agreement_private_key = 0x{tohex(plat_prik_raw)}
    authenticator_key_agreement_public_key = {{
        1: 2,
        3: -25,
        -1: 1,
        -2: h'{tohex(authnr_pub_raw[1:1+32])}',
        -3: h'{tohex(authnr_pub_raw[1+32:1+32+32])}',
    }}
    authenticator_cred_random = h'{tohex(cred_random)}'
    </xmp>

    The {{{{AuthenticationExtensionsPRFValues/first}}}} and {{{{AuthenticationExtensionsPRFValues/second}}}} inputs
    are mapped in the examples as `prf_eval_first` and `prf_eval_second`, respectively.
    The `prf_results_first` and `prf_results_second` values in the examples
    are mapped to the
    <code>{{{{AuthenticationExtensionsPRFOutputs/results}}}}.{{{{AuthenticationExtensionsPRFValues/first}}}}</code>
    and <code>{{{{AuthenticationExtensionsPRFOutputs/results}}}}.{{{{AuthenticationExtensionsPRFValues/second}}}}</code>
    outputs, respectively.
""")

    return cred_random, plat_prik_raw, authnr_prik_raw


def generate_test_vector(
        description,
        pinpr,
        cred_random,
        plat_prik_raw,
        authnr_prik_raw,
        prf_eval_first,
        prf_eval_second,
        iv_salt,
        iv_output,
):
    authnr_prik = ec.derive_private_key(int.from_bytes(authnr_prik_raw, 'big'), ec.SECP256R1())
    plat_prik = ec.derive_private_key(int.from_bytes(plat_prik_raw, 'big'), ec.SECP256R1())
    _, shared_secret = pinpr.encapsulate(authnr_prik, plat_prik.public_key())

    salt1 = sha256(b'WebAuthn PRF' + bytes([0x00]) + prf_eval_first)
    salt2 = sha256(b'WebAuthn PRF' + bytes([0x00]) + prf_eval_second) if prf_eval_second is not None else None
    salt_enc = pinpr.encrypt(shared_secret, salt1 + (salt2 or b''), iv_salt)
    assert pinpr.decrypt(shared_secret, salt_enc) == salt1 + (salt2 or b'')

    output1 = hmac_sha256(cred_random, salt1)
    output2 = hmac_sha256(cred_random, salt2) if salt2 is not None else None
    output_enc = pinpr.encrypt(shared_secret, output1 + (output2 or b''), iv_output)

    prf_results_both = pinpr.decrypt(shared_secret, output_enc)
    prf_results_first = prf_results_both[0:32]
    prf_results_second = prf_results_both[32:] if len(prf_results_both) > 32 else None

    assert prf_results_first == output1
    assert prf_results_second == output2

    output = f"""
    <xmp class="example" highlight="cddl">
    ; Inputs from Relying Party:
    prf_eval_first = h'{tohex(prf_eval_first)}'
    prf_eval_second = h'{tohex(prf_eval_second)}'

    ; Client computes:
    shared_secret = h'{tohex(shared_secret)}'
    salt1 = h'{tohex(salt1)}'
    salt2 = h'{tohex(salt2)}'
    salt_enc = h'{tohex(salt_enc)}'

    ; Authenticator computes:
    output1 = h'{tohex(output1)}'
    output2 = h'{tohex(output2)}'
    output_enc = h'{tohex(output_enc)}'

    ; Client decrypts:
    prf_results_first = h'{tohex(prf_results_first)}'
    prf_results_second = h'{tohex(prf_results_second)}'
    </xmp>
    """.strip()
    output = "\n".join(( "    " + l.strip()).rstrip() for l in output.splitlines() if "DELETE" not in l)
    print(f"- {description}:")
    print()
    print(output)
    print()


print("<!-- GENERATED CONTENT: Use test-vectors/webauthn-prf-test-vectors.py -->")

seed = b'WebAuthn PRF test vectors'
prf_eval_first = seed+bytes([0x02])
prf_eval_second = seed+bytes([0x03])
plat_prik_idx=0x04
authnr_prik_idx=0x05
cred_random_idx=0x06
cred_random, plat_prik_raw, authnr_prik_raw = setup_test_vectors(seed, plat_prik_idx, authnr_prik_idx, cred_random_idx)
iv_salt_idx_single_pp2 = 0x07
iv_output_idx_single_pp2 = 0x09
iv_salt_idx_two_pp2 = 0x08
iv_output_idx_two_pp2 = 0x0a

generate_test_vector(
    "Single input case using PIN protocol 2",
    PinProtocolV2(),
    cred_random, plat_prik_raw, authnr_prik_raw,
    prf_eval_first=prf_eval_first,
    prf_eval_second=None,
    iv_salt=prng(seed, iv_salt_idx_single_pp2)[:16],
    iv_output=prng(seed, iv_output_idx_single_pp2)[:16],
)

generate_test_vector(
    "Two input case using PIN protocol 2",
    PinProtocolV2(),
    cred_random, plat_prik_raw, authnr_prik_raw,
    prf_eval_first=prf_eval_first,
    prf_eval_second=prf_eval_second,
    iv_salt=prng(seed, iv_salt_idx_two_pp2)[:16],
    iv_output=prng(seed, iv_output_idx_two_pp2)[:16],
)

generate_test_vector(
    "Single input case using PIN protocol 1",
    PinProtocolV1(),
    cred_random, plat_prik_raw, authnr_prik_raw,
    prf_eval_first=prf_eval_first,
    prf_eval_second=None,
    iv_salt=None,
    iv_output=None,
)

print(f"""Inputs and pseudo-random values used in this section were generated as follows:

- <code>seed = UTF-8("{seed.decode("utf-8")}")</code>
- <code>prf_eval_first = seed || 0x{tohex(prf_eval_first.removeprefix(seed))}</code>
- <code>prf_eval_second = seed || 0x{tohex(prf_eval_second.removeprefix(seed))}</code>
- <code>platform_key_agreement_private_key = SHA-256(seed || 0x{tohex(plat_prik_idx)})</code>
- <code>authenticator_key_agreement_public_key = P256-Public-Key(sk)</code>
    where <code>sk = SHA-256(seed || 0x{tohex(authnr_prik_idx)})</code>
- <code>authenticator_cred_random = SHA-256(seed || 0x{tohex(cred_random_idx)})</code>
- `iv` in single-input `salt_enc` with PIN protocol 2: Truncated <code>SHA-256(seed || 0x{tohex(iv_salt_idx_single_pp2)})</code>
- `iv` in two-input `salt_enc` with PIN protocol 2: Truncated <code>SHA-256(seed || 0x{tohex(iv_salt_idx_two_pp2)})</code>
- `iv` in single-input `output_enc` with PIN protocol 2: Truncated <code>SHA-256(seed || 0x{tohex(iv_output_idx_single_pp2)})</code>
- `iv` in two-input `output_enc` with PIN protocol 2: Truncated <code>SHA-256(seed || 0x{tohex(iv_output_idx_two_pp2)})</code>
<!-- END GENERATED CONTENT: Use test-vectors/webauthn-prf-test-vectors.py -->""")
