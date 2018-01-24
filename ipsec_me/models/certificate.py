# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

from ldap3.utils.dn import parse_dn

from flask_diamond.mixins.crud import CRUDMixin
from flask_diamond.facets.database import db

from sqlalchemy.ext.declarative import declared_attr

from flask import current_app
from enum import Enum
from datetime import datetime, timedelta
from subprocess import run, PIPE
from hashlib import sha256
from OpenSSL import crypto as crypto_openssl

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pyasn1_modules import rfc2459
from pyasn1.codec.der import decoder

from uuid import uuid4
from .utils import GUID

X509_NAME_MAP = {
    'CN': NameOID.COMMON_NAME,
    'O': NameOID.ORGANIZATION_NAME,
    'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
    'C': NameOID.COUNTRY_NAME,
}

_CERTIFICATE_SETTINGS_SELFSIGN = lambda b, **extras: \
    b.issuer_name(extras['subject']) \
    .serial_number(x509.random_serial_number())

CERTIFICATE_SETTINGS_CA = lambda b, **extras: \
    b.subject_name(extras['subject']) \
    .public_key(extras['key'].public_key()) \
    .not_valid_before(datetime.utcnow()).not_valid_after( datetime.utcnow() + timedelta(**extras.get('lifetime', {'days': 20*365})) ) \
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)

_CERTIFICATE_SETTINGS_IPSEC_COMMON = lambda b, **extras: \
    b.subject_name(extras['subject']) \
    .public_key(extras['key'].public_key()) \
    .not_valid_before(datetime.utcnow()) \
    .not_valid_after( extras.get('not_valid_after', datetime.utcnow() + timedelta(**extras.get('lifetime', {'days': 15*365})) ) ) \
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
    .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False,
        key_agreement=True, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=False) \
    .add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName(name) for name in extras.get('host_names', [])] 
            + [x509.RFC822Name(name) for name in extras.get('user_emails', [])]
        ), critical=False)

CERTIFICATE_SETTINGS_IPSEC_SERVER = lambda b, **extras: \
    _CERTIFICATE_SETTINGS_IPSEC_COMMON(b, **extras) \
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ObjectIdentifier("1.3.6.1.5.5.8.2.2")]), critical=False) \

CERTIFICATE_SETTINGS_IPSEC_DEVICE = lambda b, **extras: \
    _CERTIFICATE_SETTINGS_IPSEC_COMMON(b, **extras) \
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ObjectIdentifier("1.3.6.1.5.5.8.2.2")]), critical=False) \

class CertificateStatus(Enum):
    REQUEST = "request"
    ACTIVE = "active"
    REVOKED = "revoked"

class Certificate(db.Model, CRUDMixin):
    __tablename__ = "certificate"
    id = db.Column(GUID, primary_key=True, default=uuid4)

    certificate = db.Column(db.LargeBinary())
    private_key = db.Column(db.LargeBinary())

    status = db.Column('status', db.Enum(CertificateStatus), default=CertificateStatus.ACTIVE)

    def __init__(self, DN, settings, keysize=None, sign_ca=Ellipsis, **kwargs):
        if keysize is None:
            keysize = current_app.config['RSA_KEYSIZE']

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=keysize,
            backend=default_backend()
        )
        self.private_key = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        name_parts = parse_dn(DN)
        subject = x509.Name([
            x509.NameAttribute(X509_NAME_MAP[e[0]], e[1])
            for e in name_parts
        ])

        extras = dict(kwargs)
        if sign_ca is Ellipsis: # Self-Sign
            base = _CERTIFICATE_SETTINGS_SELFSIGN( x509.CertificateBuilder(), subject=subject )
            sign_cb = lambda a: a.sign(key, hashes.SHA256(), default_backend())
            status = CertificateStatus.ACTIVE
        elif sign_ca is None: # CSR
            base = x509.CertificateRequestBuilder()
            sign_cb = lambda a: a.sign(key, hashes.SHA256(), default_backend())
            status = CertificateStatus.REQUEST
        else:
            base = x509.CertificateBuilder()
            sign_cb = lambda a: sign_ca.sign_certificate(a.serial_number(extras['serial_number']))
            status = CertificateStatus.ACTIVE

        certificate = sign_cb( settings(base, subject=subject, key=key, **extras) )
        self.certificate = certificate.public_bytes(serialization.Encoding.DER)

        print(self.prettyPrint())

    @property
    def _private_key(self):
        return serialization.load_der_private_key(self.private_key, password=None, backend=default_backend())

    @property
    def _certificate(self):
        return x509.load_der_x509_certificate(self.certificate, backend=default_backend())

    def sign_certificate(self, cert_builder):
        ## FIXME: Serial number
        return cert_builder.issuer_name(self._certificate.subject) \
            .sign(self._private_key, hashes.SHA256(), default_backend())

    def prettyPrint(self, use_openssl=True):
        if use_openssl:
            result = run(["openssl", "x509", "-noout", "-text", "-inform", "DER"], input=self.certificate, stdout=PIPE)
            return result.stdout.decode("UTF-8")
        else:
            cert = decoder.decode(self.certificate, asn1Spec=rfc2459.Certificate())[0]
            return cert.prettyPrint()

    def get_pkcs12(self, include_chain=True, password=None):
        pfx = crypto_openssl.PKCS12Type()
        pfx.set_privatekey(crypto_openssl.PKey.from_cryptography_key(self._private_key))
        pfx.set_certificate(crypto_openssl.X509.from_cryptography(self._certificate))
        if include_chain:
            pfx.set_ca_certificates(None)  ## FIXME Implement
        return pfx.export(password)

    def get_ca_pem(self):
        return b'' ## FIXME Implement

    def get_cert_pem(self):
        return self._certificate.public_bytes(serialization.Encoding.PEM)

    def get_key_pem(self, encryption_algorithm=serialization.NoEncryption()):
        return self._private_key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm)

    def get_hexhash(self):
        return sha256(self.certificate).hexdigest()
