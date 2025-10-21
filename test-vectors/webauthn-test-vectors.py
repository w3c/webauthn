import asn1
import base64
import datetime
import math

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

from fido2 import cose
from fido2.utils import sha256
from fido2.webauthn import (
    AttestationObject, AuthenticatorData, AttestedCredentialData, CollectedClientData)


RP_ID = "example.org"
RP_ID_HASH = sha256(RP_ID.encode('utf-8'))
RAND_ROOT_SEED = 'WebAuthn test vectors'

DEFAULT_ORIGIN = "https://example.org"

CERT_NOT_VALID_BEFORE = datetime.datetime.fromisoformat("2024-01-01T00:00:00Z").astimezone(datetime.timezone.utc)
CERT_NOT_VALID_AFTER = datetime.datetime.fromisoformat("3024-01-01T00:00:00Z").astimezone(datetime.timezone.utc)


def b64enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def gen_rand_idx(info: str):
    for i in range(256):
        yield RAND_ROOT_SEED, info, bytes([i])
    raise ValueError("Index out of range: " + i)


def next_prand(gen, name: str, length: int, include_base64url: bool = False) -> bytes:
    ikm, info, salt = next(gen)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info.encode('utf-8'),
        backend=default_backend(),
    )
    prnd = hkdf.derive(ikm.encode('utf-8'))
    as_hex = f""" = h'{prnd.hex()}'"""
    as_base64 = f""" = b64'{b64enc(prnd)}'""" if include_base64url else ""
    print(f"""{name}{as_hex}{as_base64}   ; Derived by: HKDF-SHA-256(IKM='{ikm}', salt=h'{salt.hex()}', info='{info}', L={length})""")
    return prnd


def to_deterministic_cert(cert, ca_key):
    """
    Workaround for python-cryptography X509CertificateBuilder not supporting deterministic ECDSA signing.
    This function takes a certificate and re-signs it using deterministic ECDSA.
    """
    dec = asn1.Decoder()
    dec.start(cert.public_bytes(serialization.Encoding.DER))
    tag, value = dec.read()
    sig = ca_key.sign(cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    enc = asn1.Encoder()
    enc.start()
    enc.write(sig, asn1.Numbers.BitString)
    sig_asn1 = enc.output()
    asn1_cert = cert.public_bytes(serialization.Encoding.DER)
    len_diff = len(sig) - len(value[2])
    assert asn1_cert[1] == 0x82
    assert asn1_cert[3] + len_diff >= 0
    assert asn1_cert[3] + len_diff <= 255
    asn1_newcert = asn1_cert[0:3] + bytes([asn1_cert[3] + len_diff]) + asn1_cert[4:-(len(value[2])+3)] + sig_asn1
    newcert = x509.load_der_x509_certificate(asn1_newcert, default_backend())
    return newcert


def gen_ca_cert():
    gen_random = gen_rand_idx("Attestation CA")
    root_key = ec.derive_private_key(int.from_bytes(next_prand(gen_random, "attestation_ca_key", 32), 'big'), ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "WebAuthn test vectors"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "W3C"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation CA"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AA"),  # AA: User-assigned ISO 3166 country code
    ])

    root_cert = to_deterministic_cert(
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(root_key.public_key())
        .serial_number(int.from_bytes(next_prand(gen_random, "attestation_ca_serial_number", 16), 'big'))
        .not_valid_before(CERT_NOT_VALID_BEFORE)
        .not_valid_after(CERT_NOT_VALID_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256()),
        root_key
    )

    print(f"""attestation_ca_cert = h'{root_cert.public_bytes(serialization.Encoding.DER).hex()}'""")

    return root_cert, root_key


def gen_att_cert(ca_cert, ca_key, rand_generator):
    att_cert_key = ec.derive_private_key(int.from_bytes(next_prand(rand_generator, "attestation_private_key", 32), 'big'), ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "WebAuthn test vectors"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "W3C"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AA"),  # AA: User-assigned ISO 3166 country code
    ])

    att_cert = to_deterministic_cert(
        x509.CertificateBuilder().subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(att_cert_key.public_key())
        .serial_number(int.from_bytes(next_prand(rand_generator, "attestation_cert_serial_number", 16), 'big'))
        .not_valid_before(CERT_NOT_VALID_BEFORE)
        .not_valid_after(CERT_NOT_VALID_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(att_cert_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256()),
        ca_key
    )

    return att_cert, att_cert_key


def gen_tpm_att_cert(ca_cert, ca_key, rand_generator):
    att_cert_key = ec.derive_private_key(int.from_bytes(next_prand(rand_generator, "attestation_private_key", 32), 'big'), ec.SECP256R1())
    subject = x509.Name([])

    att_cert = to_deterministic_cert(
        x509.CertificateBuilder().subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(att_cert_key.public_key())
        .serial_number(int.from_bytes(next_prand(rand_generator, "attestation_cert_serial_number", 16), 'big'))
        .not_valid_before(CERT_NOT_VALID_BEFORE)
        .not_valid_after(CERT_NOT_VALID_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(att_cert_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier("2.23.133.8.3")]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DirectoryName(x509.Name([x509.RelativeDistinguishedName([
                    x509.NameAttribute(x509.ObjectIdentifier("2.23.133.2.1"), "id:00000000"),
                    x509.NameAttribute(x509.ObjectIdentifier("2.23.133.2.2"), "WebAuthn test vectors"),
                    x509.NameAttribute(x509.ObjectIdentifier("2.23.133.2.3"), "id:00000000"),
                ])])),
            ]),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256()),
        ca_key
    )

    return att_cert, att_cert_key


def gen_android_key_att_cert(ca_cert, ca_key, challenge, cred_private_key, rand_generator):
    att_cert_key = cred_private_key
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "WebAuthn test vectors"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "W3C"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AA"),  # AA: User-assigned ISO 3166 country code
    ])

    asn1_encoder = asn1.Encoder()
    asn1_encoder.start()
    asn1_encoder.write([300, 0, 0, 0, challenge, b'', [], []])
    attestation_ext = asn1_encoder.output()
    att_cert = to_deterministic_cert(
        x509.CertificateBuilder().subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(att_cert_key.public_key())
        .serial_number(int.from_bytes(next_prand(rand_generator, "attestation_cert_serial_number", 16), 'big'))
        .not_valid_before(CERT_NOT_VALID_BEFORE)
        .not_valid_after(CERT_NOT_VALID_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(att_cert_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), attestation_ext),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256()),
        ca_key
    )

    return att_cert, att_cert_key


def gen_apple_att_cert(ca_cert, ca_key, auth_data, client_data, cred_private_key, rand_generator):
    att_cert_key = cred_private_key
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "WebAuthn test vectors"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "W3C"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AA"),  # AA: User-assigned ISO 3166 country code
    ])

    asn1_encoder = asn1.Encoder()
    asn1_encoder.start()
    with asn1_encoder.construct(asn1.Numbers.Sequence):
        with asn1_encoder.construct(1, cls=asn1.Classes.Context):
            asn1_encoder.write(sha256(auth_data + sha256(client_data)))
    nonce_ext = asn1_encoder.output()
    att_cert = to_deterministic_cert(
        x509.CertificateBuilder().subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(att_cert_key.public_key())
        .serial_number(int.from_bytes(next_prand(rand_generator, "attestation_cert_serial_number", 16), 'big'))
        .not_valid_before(CERT_NOT_VALID_BEFORE)
        .not_valid_after(CERT_NOT_VALID_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(att_cert_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.840.113635.100.8.2"), nonce_ext),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256()),
        ca_key
    )

    return att_cert, att_cert_key


def gen_attestation_auth_data(gen_rand, rp_id_hash, flags, sign_count, att_cred_data, extensions):
    print("; auth_data_UV_BE_BS determines the UV, BE and BS bits of the authenticator data flags, but BS is set only if BE is")
    uv_be_bs_flags = next_prand(gen_rand, 'auth_data_UV_BE_BS', 1)[0] & 0x1c
    if (uv_be_bs_flags & 0x08) == 0:
        uv_be_bs_flags = uv_be_bs_flags & (0x18 ^ 0xff)
    return AuthenticatorData.create(RP_ID_HASH, uv_be_bs_flags | flags, sign_count, att_cred_data, extensions)


def gen_assertion_auth_data(gen_rand, rp_id_hash, flags, sign_count, att_cred_data, extensions):
    print("; auth_data_UV_BS sets the UV and BS bits of the authenticator data flags, but BS is set only if BE was set in the registration")
    uv_bs_flags = next_prand(gen_rand, 'auth_data_UV_BS', 1)[0] & 0x14
    if (flags & 0x08) == 0:
        uv_bs_flags = uv_bs_flags & (0x18 ^ 0xff)
    return AuthenticatorData.create(RP_ID_HASH, uv_bs_flags | flags, sign_count, att_cred_data, extensions)


def gen_client_data(gen_rand, type, challenge, origin=DEFAULT_ORIGIN, cross_origin=False, add_top_origin=False):
    kwargs = {}

    client_data_gen_flags = next_prand(gen_rand, "client_data_gen_flags", length=1)[0]

    if add_top_origin:
        assert cross_origin
        kwargs['topOrigin'] = "https://example.com"

    print("; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1")
    if (client_data_gen_flags & 0x01) != 0:
        extraData_random = next_prand(gen_rand, "extraData_random", length=16, include_base64url=True)
        kwargs['extraData'] = f"clientDataJSON may be extended with additional fields in the future, such as this: {b64enc(extraData_random)}"

    return CollectedClientData.create(type=type, challenge=challenge, origin=origin, cross_origin=cross_origin, **kwargs)


def gen_none_attestation(gen_rand, challenge, credential_id_length, public_key, origin=DEFAULT_ORIGIN, cross_origin=False, add_top_origin=False):
    client_data = gen_client_data(
        gen_rand,
        "webauthn.create",
        challenge,
        origin=origin,
        cross_origin=cross_origin,
        add_top_origin=add_top_origin,
    )

    aaguid = next_prand(gen_rand, "aaguid", 16)
    credential_id = next_prand(gen_rand, "credential_id", credential_id_length)
    att_cred_data = AttestedCredentialData.create(aaguid, credential_id, public_key)
    auth_data = gen_attestation_auth_data(gen_rand, RP_ID_HASH, 0x41, 0, att_cred_data, None)

    att_obj = AttestationObject.create("none", auth_data, {})

    print()
    print(f"clientDataJSON = h'{client_data.hex()}'")
    print(f"attestationObject = h'{att_obj.hex()}'")
    return att_obj, client_data


def gen_packed_self_attestation(gen_rand, challenge, credential_id_length, private_key, public_key, origin=DEFAULT_ORIGIN, cross_origin=False, add_top_origin=False):
    client_data = gen_client_data(
        gen_rand,
        "webauthn.create",
        challenge,
        origin=origin,
        cross_origin=cross_origin,
        add_top_origin=add_top_origin,
    )

    aaguid = next_prand(gen_rand, "aaguid", 16)
    credential_id = next_prand(gen_rand, "credential_id", credential_id_length)
    att_cred_data = AttestedCredentialData.create(aaguid, credential_id, public_key)
    auth_data = gen_attestation_auth_data(gen_rand, RP_ID_HASH, 0x41, 0, att_cred_data, None)

    att_obj = AttestationObject.create("packed", auth_data, {
        "alg": public_key.ALGORITHM,
        "sig": private_key.sign(auth_data + sha256(client_data), ec.ECDSA(hashes.SHA256(), deterministic_signing=True)),
    })

    print()
    print(f"clientDataJSON = h'{client_data.hex()}'")
    print(f"attestationObject = h'{att_obj.hex()}'")
    return att_obj, client_data


def gen_packed_attestation(gen_rand, challenge, credential_id_length, public_key, origin=DEFAULT_ORIGIN, cross_origin=False, add_top_origin=False):
    client_data = gen_client_data(
        gen_rand,
        "webauthn.create",
        challenge,
        origin=origin,
        cross_origin=cross_origin,
        add_top_origin=add_top_origin,
    )

    aaguid = next_prand(gen_rand, "aaguid", 16)
    credential_id = next_prand(gen_rand, "credential_id", credential_id_length)
    att_cred_data = AttestedCredentialData.create(aaguid, credential_id, public_key)
    auth_data = gen_attestation_auth_data(gen_rand, RP_ID_HASH, 0x41, 0, att_cred_data, None)

    att_cert, att_key = gen_att_cert(att_ca_cert, att_ca_key, gen_rand)
    att_obj = AttestationObject.create("packed", auth_data, {
        "alg": cose.ES256.ALGORITHM,
        "sig": att_key.sign(auth_data + sha256(client_data), ec.ECDSA(hashes.SHA256(), deterministic_signing=True)),
        "x5c": [att_cert.public_bytes(serialization.Encoding.DER)]
    })

    print()
    print(f"clientDataJSON = h'{client_data.hex()}'")
    print(f"attestationObject = h'{att_obj.hex()}'")
    return att_obj, client_data


def gen_tpm_attestation_statement(gen_rand, auth_data: AuthenticatorData, clientDataJSON: bytes):
    tpm_magic = base64.b64decode('/1RDRw==')
    tpm_type = base64.b64decode('gBc=')

    cose_key_alg = auth_data.credential_data.public_key.ALGORITHM
    assert cose_key_alg == cose.ES256.ALGORITHM
    hash_id = bytes.fromhex('000B')
    sign_alg = bytes.fromhex('0023')
    assert hash_id == bytes.fromhex('000B');
    hash_func = sha256
    extra_data = hash_func(auth_data + sha256(clientDataJSON))

    assert auth_data.credential_data.public_key[1] == 2  # kty == 2
    parameters = (
        bytes.fromhex('0010')
        + bytes.fromhex('0010')
        + bytes.fromhex('0003')
        + bytes.fromhex('0010')
    )
    unique = (
        int.to_bytes(len(auth_data.credential_data.public_key[-2]), 2, 'big')
        + auth_data.credential_data.public_key[-2]
        + int.to_bytes(len(auth_data.credential_data.public_key[-3]), 2, 'big')
        + auth_data.credential_data.public_key[-3]
    )

    pub_area = (
        sign_alg
        + hash_id
        + int.to_bytes(1 << 18, 4, 'big')
        + int.to_bytes(0, 2, 'big')
        + parameters
        + unique
    )

    qualified_signer = b''
    clock_info = bytes.fromhex("0000000000000000111111112222222233")
    firmware_version = bytes.fromhex("0000000000000000")
    attested_name = hash_id + hash_func(pub_area)
    attested_qualified_name = b''

    cert_info = (
        tpm_magic
        + tpm_type
        + int.to_bytes(len(qualified_signer), 2, 'big')
        + qualified_signer
        + int.to_bytes(len(extra_data), 2, 'big')
        + extra_data
        + clock_info
        + firmware_version
        + int.to_bytes(len(attested_name), 2, 'big')
        + attested_name
        + int.to_bytes(len(attested_qualified_name), 2, 'big')
        + attested_qualified_name
    )

    att_cert, att_key = gen_tpm_att_cert(att_ca_cert, att_ca_key, gen_rand)
    sig = att_key.sign(cert_info, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    return {
        "ver": "2.0",
        "alg": cose.ES256.ALGORITHM,
        "x5c": [att_cert.public_bytes(serialization.Encoding.DER)],
        "sig": sig,
        "certInfo": cert_info,
        "pubArea": pub_area,
    }


def gen_tpm_attestation(gen_rand, challenge, credential_id_length, public_key, origin=DEFAULT_ORIGIN):
    client_data = gen_client_data(gen_rand, "webauthn.create", challenge, origin=origin)

    aaguid = next_prand(gen_rand, "aaguid", 16)
    credential_id = next_prand(gen_rand, "credential_id", credential_id_length)
    att_cred_data = AttestedCredentialData.create(aaguid, credential_id, public_key)
    auth_data = gen_attestation_auth_data(gen_rand, RP_ID_HASH, 0x41, 0, att_cred_data, None)

    att_obj = AttestationObject.create("tpm", auth_data, gen_tpm_attestation_statement(gen_rand, auth_data, client_data))

    print()
    print(f"clientDataJSON = h'{client_data.hex()}'")
    print(f"attestationObject = h'{att_obj.hex()}'")
    return att_obj, client_data


def gen_android_key_attestation(gen_rand, challenge, credential_id_length, private_key, public_key, origin=DEFAULT_ORIGIN):
    client_data = gen_client_data(gen_rand, "webauthn.create", challenge, origin=origin)

    aaguid = next_prand(gen_rand, "aaguid", 16)
    credential_id = next_prand(gen_rand, "credential_id", credential_id_length)
    att_cred_data = AttestedCredentialData.create(aaguid, credential_id, public_key)
    auth_data = gen_attestation_auth_data(gen_rand, RP_ID_HASH, 0x41, 0, att_cred_data, None)

    att_cert, att_key = gen_android_key_att_cert(att_ca_cert, att_ca_key, sha256(client_data), private_key, gen_rand)
    att_obj = AttestationObject.create("android-key", auth_data, {
        "alg": cose.ES256.ALGORITHM,
        "sig": att_key.sign(auth_data + sha256(client_data), ec.ECDSA(hashes.SHA256(), deterministic_signing=True)),
        "x5c": [att_cert.public_bytes(serialization.Encoding.DER)]
    })

    print()
    print(f"clientDataJSON = h'{client_data.hex()}'")
    print(f"attestationObject = h'{att_obj.hex()}'")
    return att_obj, client_data


def gen_apple_attestation(gen_rand, challenge, credential_id_length, private_key, public_key, origin=DEFAULT_ORIGIN):
    client_data = gen_client_data(gen_rand, "webauthn.create", challenge, origin=origin)

    aaguid = next_prand(gen_rand, "aaguid", 16)
    credential_id = next_prand(gen_rand, "credential_id", credential_id_length)
    att_cred_data = AttestedCredentialData.create(aaguid, credential_id, public_key)
    auth_data = gen_attestation_auth_data(gen_rand, RP_ID_HASH, 0x41, 0, att_cred_data, None)

    att_cert, att_key = gen_apple_att_cert(att_ca_cert, att_ca_key, auth_data, client_data, private_key, gen_rand)
    att_obj = AttestationObject.create("apple", auth_data, {
        "x5c": [att_cert.public_bytes(serialization.Encoding.DER)]
    })

    print()
    print(f"clientDataJSON = h'{client_data.hex()}'")
    print(f"attestationObject = h'{att_obj.hex()}'")
    return att_obj, client_data


def gen_fido_u2f_attestation(gen_rand, challenge, credential_id_length, public_key, origin=DEFAULT_ORIGIN):
    client_data = gen_client_data(gen_rand, "webauthn.create", challenge, origin=origin)

    aaguid = next_prand(gen_rand, "aaguid", 16)
    credential_id = next_prand(gen_rand, "credential_id", credential_id_length)
    att_cred_data = AttestedCredentialData.create(aaguid, credential_id, public_key)
    public_key_raw = bytes([0x04]) + public_key[-2] + public_key[-3]
    auth_data = AuthenticatorData.create(RP_ID_HASH, 0x41, 0, att_cred_data, None)

    att_cert, att_key = gen_att_cert(att_ca_cert, att_ca_key, gen_rand)
    att_obj = AttestationObject.create("fido-u2f", auth_data, {
        "sig": att_key.sign(
            bytes([0]) + RP_ID_HASH + sha256(client_data) + credential_id + public_key_raw,
            ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
        ),
        "x5c": [att_cert.public_bytes(serialization.Encoding.DER)]
    })

    print()
    print(f"clientDataJSON = h'{client_data.hex()}'")
    print(f"attestationObject = h'{att_obj.hex()}'")
    return att_obj, client_data


def gen_assertion(gen_rand, be_flag, challenge, pri_key, sign_args, origin=DEFAULT_ORIGIN, cross_origin=False, add_top_origin=False):
    client_data = gen_client_data(
        gen_rand,
        "webauthn.get",
        challenge,
        origin=origin,
        cross_origin=cross_origin,
        add_top_origin=add_top_origin,
    )

    auth_data = gen_assertion_auth_data(gen_rand, RP_ID_HASH, be_flag | 0x01, 0, b'', None)
    sig = pri_key.sign(auth_data + sha256(client_data), *sign_args)

    print()
    print(f"authenticatorData = h'{auth_data.hex()}'")
    print(f"clientDataJSON = h'{client_data.hex()}'")
    print(f"signature = h'{sig.hex()}'")


def test_vectors_none_ecdsa(
        description,
        info,
        private_key_length,
        crv,
        cose_class,
        credential_id_length=32,
        challenge_length=32,
        origin=DEFAULT_ORIGIN,
        cross_origin=False,
        add_top_origin=False,
):
    print()
    print()
    print(description)
    print()
    print('[=registration ceremony|Registration=]:')
    print('<xmp class="example" highlight="cddl">')
    gen_rand = gen_rand_idx(info)

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    pri_key = ec.derive_private_key(int.from_bytes(next_prand(gen_rand, "credential_private_key", private_key_length), 'big'), crv)
    public_key = cose_class.from_cryptography_key(pri_key.public_key())
    att_obj, client_data = gen_none_attestation(gen_rand, challenge, credential_id_length, public_key, origin=origin, cross_origin=cross_origin, add_top_origin=add_top_origin)

    print('</xmp>')
    print()
    print('[=authentication ceremony|Authentication=]:')
    print('<xmp class="example" highlight="cddl">')

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    gen_assertion(
        gen_rand,
        att_obj.auth_data.flags & 0x08,
        challenge,
        pri_key,
        [ec.ECDSA(cose_class._HASH_ALG, deterministic_signing=True)],
        cross_origin=cross_origin,
        add_top_origin=add_top_origin,
    )
    print('</xmp>')


def test_vectors_packed_self_ecdsa(
        description,
        info,
        private_key_length,
        crv,
        cose_class,
        credential_id_length=32,
        challenge_length=32,
):
    print()
    print()
    print(description)
    print()
    print('[=registration ceremony|Registration=]:')
    print('<xmp class="example" highlight="cddl">')
    gen_rand = gen_rand_idx(info)

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    pri_key = ec.derive_private_key(int.from_bytes(next_prand(gen_rand, "credential_private_key", private_key_length), 'big'), crv)
    public_key = cose_class.from_cryptography_key(pri_key.public_key())

    att_obj, client_data = gen_packed_self_attestation(gen_rand, challenge, credential_id_length, pri_key, public_key)

    print('</xmp>')
    print()
    print('[=authentication ceremony|Authentication=]:')
    print('<xmp class="example" highlight="cddl">')

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    gen_assertion(
        gen_rand,
        att_obj.auth_data.flags & 0x08,
        challenge,
        pri_key,
        [ec.ECDSA(cose_class._HASH_ALG, deterministic_signing=True)],
    )
    print('</xmp>')


def test_vectors_packed_ecdsa(
        description,
        info,
        private_key_length,
        crv,
        cose_class,
        credential_id_length=32,
        challenge_length=32,
):
    print()
    print()
    print(description)
    print()
    print('[=registration ceremony|Registration=]:')
    print('<xmp class="example" highlight="cddl">')
    gen_rand = gen_rand_idx(info)

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    pri_key = ec.derive_private_key(int.from_bytes(next_prand(gen_rand, "credential_private_key", private_key_length), 'big'), crv)
    public_key = cose_class.from_cryptography_key(pri_key.public_key())
    att_obj, client_data = gen_packed_attestation(gen_rand, challenge, credential_id_length, public_key)

    print('</xmp>')
    print()
    print('[=authentication ceremony|Authentication=]:')
    print('<xmp class="example" highlight="cddl">')

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    gen_assertion(
        gen_rand,
        att_obj.auth_data.flags & 0x08,
        challenge,
        pri_key,
        [ec.ECDSA(cose_class._HASH_ALG, deterministic_signing=True)],
    )
    print('</xmp>')


def test_vectors_packed_rsa(
        description,
        info,
        cose_class,
        credential_id_length=32,
        challenge_length=32,
):
    print()
    print()
    print(description)
    print()
    print('[=registration ceremony|Registration=]:')
    print('<xmp class="example" highlight="cddl">')
    gen_rand = gen_rand_idx(info)

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()

    print("; The two smallest Mersenne primes 2^p - 1 where p >= 1024")
    pri_key_p = 2**1279 - 1
    pri_key_q = 2**2203 - 1
    print(f"private_key_p = 2^1279 - 1 = h'{int.to_bytes(pri_key_p, math.ceil(1279/8)).hex()}'")
    print(f"private_key_q = 2^2203 - 1 = h'{int.to_bytes(pri_key_q, math.ceil(2203/8)).hex()}'")
    pub_key_e = 65537
    pri_key_d = rsa.rsa_recover_private_exponent(pub_key_e, pri_key_p, pri_key_q)
    pri_key = rsa.RSAPrivateNumbers(
        p=pri_key_p,
        q=pri_key_q,
        d=pri_key_d,
        dmp1=rsa.rsa_crt_dmp1(pri_key_d, pri_key_p),
        dmq1=rsa.rsa_crt_dmq1(pri_key_d, pri_key_q),
        iqmp=rsa.rsa_crt_iqmp(pri_key_p, pri_key_q),
        public_numbers=rsa.RSAPublicNumbers(e=pub_key_e, n=pri_key_p * pri_key_q)
    ).private_key()
    public_key = cose_class.from_cryptography_key(pri_key.public_key())
    att_obj, client_data = gen_packed_attestation(gen_rand, challenge, credential_id_length, public_key)

    print('</xmp>')
    print()
    print('[=authentication ceremony|Authentication=]:')
    print('<xmp class="example" highlight="cddl">')

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    gen_assertion(
        gen_rand,
        att_obj.auth_data.flags & 0x08,
        challenge,
        pri_key,
        [padding.PKCS1v15(), cose_class._HASH_ALG],
    )
    print('</xmp>')


def test_vectors_packed_eddsa(
        description,
        info,
        cose_class,
        cryptography_prikey_class,
        private_key_length,
        credential_id_length=32,
        challenge_length=32,
):
    print()
    print()
    print(description)
    print()
    print('[=registration ceremony|Registration=]:')
    print('<xmp class="example" highlight="cddl">')
    gen_rand = gen_rand_idx(info)

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()

    pri_key = cryptography_prikey_class.from_private_bytes(next_prand(gen_rand, "private_key", private_key_length))
    public_key = cose_class.from_cryptography_key(pri_key.public_key())
    att_obj, client_data = gen_packed_attestation(gen_rand, challenge, credential_id_length, public_key)

    print('</xmp>')
    print()
    print('[=authentication ceremony|Authentication=]:')
    print('<xmp class="example" highlight="cddl">')

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    gen_assertion(
        gen_rand,
        att_obj.auth_data.flags & 0x08,
        challenge,
        pri_key,
        [],
    )
    print('</xmp>')


def test_vectors_fido_u2f(
        description,
        info,
        credential_id_length=32,
        challenge_length=32,
):
    print()
    print()
    print(description)
    print()
    print('[=registration ceremony|Registration=]:')
    print('<xmp class="example" highlight="cddl">')
    gen_rand = gen_rand_idx(info)

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()

    pri_key = ec.derive_private_key(int.from_bytes(next_prand(gen_rand, "credential_private_key", 32), 'big'), ec.SECP256R1())
    public_key = cose.ES256.from_cryptography_key(pri_key.public_key())
    att_obj, client_data = gen_fido_u2f_attestation(gen_rand, challenge, credential_id_length, public_key)

    print('</xmp>')
    print()
    print('[=authentication ceremony|Authentication=]:')
    print('<xmp class="example" highlight="cddl">')

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    gen_assertion(
        gen_rand,
        att_obj.auth_data.flags & 0x08,
        challenge,
        pri_key,
        [ec.ECDSA(cose.ES256._HASH_ALG, deterministic_signing=True)],
    )
    print('</xmp>')


def test_vectors_tpm_ecdsa(
        description,
        info,
        private_key_length,
        crv,
        cose_class,
        credential_id_length=32,
        challenge_length=32,
):
    print()
    print()
    print(description)
    print()
    print('[=registration ceremony|Registration=]:')
    print('<xmp class="example" highlight="cddl">')
    gen_rand = gen_rand_idx(info)

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()

    pri_key = ec.derive_private_key(int.from_bytes(next_prand(gen_rand, "credential_private_key", private_key_length), 'big'), crv)
    public_key = cose_class.from_cryptography_key(pri_key.public_key())
    att_obj, client_data = gen_tpm_attestation(gen_rand, challenge, credential_id_length, public_key)

    print('</xmp>')
    print()
    print('[=authentication ceremony|Authentication=]:')
    print('<xmp class="example" highlight="cddl">')

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    gen_assertion(
        gen_rand,
        att_obj.auth_data.flags & 0x08,
        challenge,
        pri_key,
        [ec.ECDSA(cose_class._HASH_ALG, deterministic_signing=True)],
    )
    print('</xmp>')


def test_vectors_android_key_ecdsa(
        description,
        info,
        private_key_length,
        crv,
        cose_class,
        credential_id_length=32,
        challenge_length=32,
):
    print()
    print()
    print(description)
    print()
    print('[=registration ceremony|Registration=]:')
    print('<xmp class="example" highlight="cddl">')
    gen_rand = gen_rand_idx(info)

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()

    pri_key = ec.derive_private_key(int.from_bytes(next_prand(gen_rand, "credential_private_key", private_key_length), 'big'), crv)
    public_key = cose_class.from_cryptography_key(pri_key.public_key())
    att_obj, client_data = gen_android_key_attestation(gen_rand, challenge, credential_id_length, pri_key, public_key)

    print('</xmp>')
    print()
    print('[=authentication ceremony|Authentication=]:')
    print('<xmp class="example" highlight="cddl">')

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    gen_assertion(
        gen_rand,
        att_obj.auth_data.flags & 0x08,
        challenge,
        pri_key,
        [ec.ECDSA(cose_class._HASH_ALG, deterministic_signing=True)],
    )
    print('</xmp>')


def test_vectors_apple_ecdsa(
        description,
        info,
        private_key_length,
        crv,
        cose_class,
        credential_id_length=32,
        challenge_length=32,
):
    print()
    print()
    print(description)
    print()
    print('[=registration ceremony|Registration=]:')
    print('<xmp class="example" highlight="cddl">')
    gen_rand = gen_rand_idx(info)

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()

    pri_key = ec.derive_private_key(int.from_bytes(next_prand(gen_rand, "credential_private_key", private_key_length), 'big'), crv)
    public_key = cose_class.from_cryptography_key(pri_key.public_key())
    att_obj, client_data = gen_apple_attestation(gen_rand, challenge, credential_id_length, pri_key, public_key)

    print('</xmp>')
    print()
    print('[=authentication ceremony|Authentication=]:')
    print('<xmp class="example" highlight="cddl">')

    challenge = next_prand(gen_rand, "challenge", challenge_length)
    print()
    gen_assertion(
        gen_rand,
        att_obj.auth_data.flags & 0x08,
        challenge,
        pri_key,
        [ec.ECDSA(cose_class._HASH_ALG, deterministic_signing=True)],
    )
    print('</xmp>')



print("<!-- GENERATED CONTENT: Use test-vectors/webauthn-test-vectors.py -->")
print('''## Attestation trust root certificate ## {#sctn-test-vectors-attestation-root-cert}

All examples that include [=attestation=] use the attestation trust root certificate
given as `attestation_ca_cert` below, encoded in X.509 DER [[RFC5280]]:

<xmp class="example" highlight="cddl">''')
att_ca_cert, att_ca_key = gen_ca_cert()
print('</xmp>')

test_vectors_none_ecdsa(
    "## ES256 Credential with No Attestation ## {#sctn-test-vectors-none-es256}",
    'none.ES256',
    32,
    ec.SECP256R1(),
    cose.ES256,
)

test_vectors_packed_self_ecdsa(
    "## ES256 Credential with Self Attestation ## {#sctn-test-vectors-packed-self-es256}",
    'packed-self.ES256',
    32,
    ec.SECP256R1(),
    cose.ES256,
)

# test_vectors_none_ecdsa(
#     '## ES256 Credential with subdomain origin ## {#sctn-test-vectors-none-es256-subdomain-origin}',
#     'none.ES256.subdomain-origin',
#     32,
#     ec.SECP256R1(),
#     cose.ES256,
#     origin="https://sub.example.org",
# )

test_vectors_none_ecdsa(
    '## ES256 Credential with "crossOrigin": true in clientDataJSON ## {#sctn-test-vectors-none-es256-crossOrigin}',
    'none.ES256.crossOrigin',
    32,
    ec.SECP256R1(),
    cose.ES256,
    cross_origin=True,
    add_top_origin=False,
)

test_vectors_none_ecdsa(
    '## ES256 Credential with "topOrigin" in clientDataJSON ## {#sctn-test-vectors-none-es256-topOrigin}',
    'none.ES256.topOrigin',
    32,
    ec.SECP256R1(),
    cose.ES256,
    cross_origin=True,
    add_top_origin=True,
)

test_vectors_none_ecdsa(
    "## ES256 Credential with very long credential ID ## {#sctn-test-vectors-none-es256-long-credential-id}",
    'none.ES256.long-credential-id',
    32,
    ec.SECP256R1(),
    cose.ES256,
    credential_id_length=1023,
)

test_vectors_packed_ecdsa(
    "## Packed Attestation with ES256 Credential ## {#sctn-test-vectors-packed-es256}",
    'packed.ES256',
    32,
    ec.SECP256R1(),
    cose.ES256,
)
test_vectors_packed_ecdsa(
    "## Packed Attestation with ES384 Credential ## {#sctn-test-vectors-packed-es384}",
    'packed.ES384',
    48,
    ec.SECP384R1(),
    cose.ES384,
)
test_vectors_packed_ecdsa(
    "## Packed Attestation with ES512 Credential ## {#sctn-test-vectors-packed-es512}",
    'packed.ES512',
    65,
    ec.SECP521R1(),
    cose.ES512,
    challenge_length=128,
)
test_vectors_packed_rsa(
    "## Packed Attestation with RS256 Credential ## {#sctn-test-vectors-packed-rs256}",
    'packed.RS256',
    cose.RS256,
)
test_vectors_packed_eddsa(
    "## Packed Attestation with Ed25519 Credential ## {#sctn-test-vectors-packed-eddsa}",
    'packed.EdDSA',
    cose.EdDSA,
    ed25519.Ed25519PrivateKey,
    32,
)
test_vectors_packed_eddsa(
    "## Packed Attestation with Ed448 Credential ## {#sctn-test-vectors-packed-ed448}",
    'packed.Ed448',
    cose.Ed448,
    ed448.Ed448PrivateKey,
    57,
)

test_vectors_tpm_ecdsa(
    "## TPM Attestation with ES256 Credential ## {#sctn-test-vectors-tpm-es256}",
    'tpm.ES256',
    32,
    ec.SECP256R1(),
    cose.ES256,
)

test_vectors_android_key_ecdsa(
    "## Android Key Attestation with ES256 Credential ## {#sctn-test-vectors-android-key-es256}",
    'android-key.ES256',
    32,
    ec.SECP256R1(),
    cose.ES256,
)

test_vectors_apple_ecdsa(
    "## Apple Anonymous Attestation with ES256 Credential ## {#sctn-test-vectors-apple-es256}",
    'apple.ES256',
    32,
    ec.SECP256R1(),
    cose.ES256,
)

test_vectors_fido_u2f(
    "## FIDO U2F Attestation with ES256 Credential ## {#sctn-test-vectors-fido-u2f-es256}",
    'fido-u2f.ES256',
)

print("<!-- END GENERATED CONTENT: Use test-vectors/webauthn-test-vectors.py -->")
