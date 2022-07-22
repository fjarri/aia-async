import ssl
from typing import List, Iterable, Sequence
from urllib.parse import urlsplit

import anyio
import cryptography.x509 as cryptography
from cryptography.x509 import ExtensionNotFound, ExtensionOID, AuthorityInformationAccessOID
import OpenSSL.crypto as openssl


def load_certificate_der(certificate_der: bytes) -> openssl.X509:
    return openssl.load_certificate(openssl.FILETYPE_ASN1, certificate_der)


def dump_certificate_der(certificate: openssl.X509) -> bytes:
    return openssl.dump_certificate(openssl.FILETYPE_ASN1, certificate)


def get_aia_ca_issuers(certificate: openssl.X509) -> List[str]:

    # PyOpenSSL only gives basic access to extensions,
    # we need to drop to the `cryptography` level to get CA issuers.
    backend_certificate = certificate.to_cryptography()

    try:
        aia_oid = cryptography.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        aia = backend_certificate.extensions.get_extension_for_oid(aia_oid)
    except cryptography.ExtensionNotFound:
        return []

    aia_ca_issuers = []
    for descr in aia.value._descriptions:
        if descr.access_method == cryptography.AuthorityInformationAccessOID.CA_ISSUERS:
            aia_ca_issuers.append(descr.access_location.value)

    return aia_ca_issuers


class TrustedCertificates:

    @classmethod
    def from_ssl_context(cls, context: ssl.SSLContext):
        trusted_certs = [load_certificate_der(cert_der) for cert_der in context.get_ca_certs(True)]
        return cls(trusted_certs)

    @classmethod
    def default(cls):
        return cls.from_ssl_context(ssl.create_default_context())

    @staticmethod
    def _fingerprint(certificate: openssl.X509) -> bytes:
        return certificate.digest("SHA256")

    def __init__(self, certificates: Iterable[openssl.X509]):
        self._fingerprints = {self._fingerprint(certificate) for certificate in certificates}

    def __contains__(self, certificate: openssl.X509):
        return self._fingerprint(certificate) in self._fingerprints


async def get_host_cert(host: str, port: int) -> openssl.X509:
    """
    Get the certificate for the taget host
    without checking it (leaf certificate).
    """

    # Since we just want to download the certificate, skip all the checks
    context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    stream = await anyio.connect_tcp(host, port, tls=True, ssl_context=context)
    certificate_der = stream.extra_attributes[anyio.streams.tls.TLSAttribute.peer_certificate_binary]()

    return load_certificate_der(certificate_der)


async def get_ca_issuer_cert(url: str) -> openssl.X509:
    """
    Get an intermediary certificate in the chain
    from a given URL which should had been found
    as the CA Issuer URI in the AIA extension
    of the previous "node" (certificate) of the chain.
    """
    split = urlsplit(url)
    if split.scheme != "http":
        raise Exception("Invalid CA issuer certificate URI protocol")

    # Constructing an HTTP request and parsing the response manually
    # to avoid depending on a specific async HTTP library.
    # For sync operation we could have used the standard library.

    stream = await anyio.connect_tcp(split.netloc, split.port or 80)
    request = (
        f"GET {split.path} HTTP/1.1\r\n"
        f"Host:{split.netloc}\r\n"
        "Connection:close\r\n\r\n").encode()
    await stream.send(request)
    response = await stream.receive()

    # HTTP response has several headers separated by `\r\n`,
    # and the body is separated from the headers by '\r\n\r\n'.
    header_string, _, body = response.partition(b'\r\n\r\n')
    headers = header_string.split(b'\r\n')
    # We only need the first header that contains the status code
    http_version, status_code, *_ = headers[0].split(b' ')
    if status_code != b"200":
        raise Exception(f"Failed to download a CA certificate from {url} (status {status_code.decode()}")

    return load_certificate_der(body)


async def aia_chase(trusted_certificates: TrustedCertificates, host: str, port: int):

    certificates = []

    certificate = await get_host_cert(host, port)
    while True:
        certificates.append(certificate)

        issuer = certificate.get_issuer()
        subject = certificate.get_subject()

        if certificate in trusted_certificates:
            # Hit a trusted certificate
            return True, certificates

        if issuer == subject:
            # Hit a self-signed certificate
            return False, certificates

        issuers = get_aia_ca_issuers(certificate)
        if not issuers:
            raise Exception("The certificate is not a root one, but it does not contain any CA issuers")

        # TODO: try all available?
        certificate = await get_ca_issuer_cert(issuers[0])


def validate_certificate_chain(certificates: Sequence[openssl.X509]):
    """
    Validates a given certificate chain, ordered from leaf to root.
    """
    if len(certificates) < 2:
        # Trivial case
        return

    store = openssl.X509Store()
    store.add_cert(certificates[-1]) # Trust the root certificate
    try:
        openssl.X509StoreContext(
            store,
            certificates[0],
            certificates[1:-1]).verify_certificate()
    except openssl.X509StoreContextError as exc:
        raise Exception("Failed to validate the certificate chain")


async def make_context(host: str, port: int, purpose=ssl.Purpose.SERVER_AUTH, allow_self_signed: bool = False) -> ssl.SSLContext:
    """
    Returns an ``SSLContext`` instance for a single host name
    that gets (and validates) its certificate chain from AIA.
    """
    # TODO: expose this for caching purposes
    context = ssl.create_default_context(purpose=purpose)
    trusted_certificates = TrustedCertificates.from_ssl_context(context)
    trusted_root, certificates = await aia_chase(trusted_certificates, host, port)

    if not trusted_root and not allow_self_signed:
        raise Exception("The certificate chain ends in a self-signed certificate")

    validate_certificate_chain(certificates)

    if trusted_root:
        chain = certificates[:-1] # root cert is already in the context
    else:
        chain = certificates

    cadata = b"".join(dump_certificate_der(certificate) for certificate in chain)
    context.load_verify_locations(cadata=cadata)
    return context
