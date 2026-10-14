"""Hermetic TLS handshake against a loopback server (no network, no Freebox).

Real Freebox leaf certificates carry no Authority Key Identifier, which
OpenSSL's X509_STRICT (on by default since Python 3.13) rejects. A throwaway
CA + AKI-less leaf generated in tmp_path reproduces that shape; the project
context must accept it while still enforcing hostname and CA pinning.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from freebox_mcp.client import _verify
from freebox_mcp.config import Settings

HOST = "mafreebox.freebox.fr"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn: str) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
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
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _leaf_without_aki(
    ca: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Mirror the Freebox leaf: SAN + serverAuth, but no AKI/SKI."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("test.fbxos.fr"))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    assert not any(e.oid == x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER for e in cert.extensions)
    return cert, key


def _pem(path: Path, *items: bytes) -> Path:
    path.write_bytes(b"".join(items))
    return path


@pytest.fixture
def pki(tmp_path):
    ca, ca_key = _ca("Test Freebox Root CA")
    foreign, _ = _ca("Foreign Root CA")
    leaf, leaf_key = _leaf_without_aki(ca, ca_key)
    pem = serialization.Encoding.PEM
    return {
        "ca": _pem(tmp_path / "ca.pem", ca.public_bytes(pem)),
        "foreign": _pem(tmp_path / "foreign.pem", foreign.public_bytes(pem)),
        "chain": _pem(tmp_path / "leaf.pem", leaf.public_bytes(pem)),
        "key": _pem(
            tmp_path / "leaf.key",
            leaf_key.private_bytes(
                pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ),
        ),
    }


@pytest.fixture
def server(pki):
    """One-shot-per-connection TLS server on 127.0.0.1 serving the AKI-less leaf."""
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(pki["chain"], pki["key"])
    sock = socket.create_server(("127.0.0.1", 0))
    sock.settimeout(0.1)  # lets the loop notice `stop` promptly
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.settimeout(5)
            with conn:
                try:
                    with sctx.wrap_socket(conn, server_side=True):
                        pass
                except (ssl.SSLError, OSError):
                    pass  # client rejected the handshake

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield sock.getsockname()[1]
    stop.set()
    sock.close()
    t.join(timeout=5)


def _handshake(ctx: ssl.SSLContext, port: int, sni: str) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            assert tls.version() in {"TLSv1.2", "TLSv1.3"}


def _project_ctx(cafile: Path) -> ssl.SSLContext:
    # Same path the client/discovery use, with the CA bundle swapped for the test CA.
    return _verify(Settings(cert_bundle=cafile))


def test_accepts_valid_leaf_without_aki(pki, server):
    _handshake(_project_ctx(pki["ca"]), server, HOST)


def test_rejects_wrong_hostname(pki, server):
    with pytest.raises(ssl.SSLCertVerificationError, match="Hostname mismatch"):
        _handshake(_project_ctx(pki["ca"]), server, "evil.example")


def test_rejects_foreign_ca(pki, server):
    with pytest.raises(ssl.SSLCertVerificationError, match="unable to get local issuer"):
        _handshake(_project_ctx(pki["foreign"]), server, HOST)
