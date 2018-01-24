# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

from flask_diamond.models.user import User
from flask_diamond.models.role import Role

from flask_diamond.mixins.crud import CRUDMixin
from flask_diamond.facets.database import db

from sqlalchemy.ext.declarative import declared_attr

from passlib import pwd
from flask import current_app
from uuid import uuid4
from string import ascii_lowercase, digits

from enum import Enum

from .certificate import Certificate, CertificateStatus, CERTIFICATE_SETTINGS_CA, CERTIFICATE_SETTINGS_IPSEC_SERVER, CERTIFICATE_SETTINGS_IPSEC_DEVICE
from .utils import GUID

ca_vpn_table = db.Table('ca_vpn_table',
    db.Column('vpn_server_id', GUID, db.ForeignKey('vpn_server.id')),
    db.Column('certificate_authority_id', GUID, db.ForeignKey('certificate_authority.id'))
)

class SerialNumberMixin(object):
    next_serial_number = db.Column('next_serial_number', db.Integer, default=1, server_default='1')

    def get_next_serial_number(self):
        ca = db.session.query(self.__class__).with_lockmode('update').filter_by(id=self.id).one()
        serial_number = ca.next_serial_number
        ca.next_serial_number += 1
        db.session.flush()
        db.session.expire(self)
        return serial_number


class CertificateAuthority(db.Model, CRUDMixin, SerialNumberMixin):
    __tablename__ = "certificate_authority"
    id = db.Column(GUID, primary_key=True, default=uuid4)
    rdn = db.Column(db.String())
    base_dn = db.Column(db.String())

    certificate_id = db.Column('certificate_id', GUID, db.ForeignKey('certificate.id'))
    certificate = db.relationship('Certificate')

    VPNs = db.relationship(
        "VPNServer",
        secondary=ca_vpn_table,
        back_populates="CAs")

    @property
    def DN(self):
        if self.base_dn:
            return "{0}, {1}".format(self.rdn, self.base_dn)
        else:
            return self.rdn

    def __init__(self, rdn, base_dn="", settings=CERTIFICATE_SETTINGS_CA):
        self.rdn = rdn
        self.base_dn = base_dn
        self.certificate = Certificate.create(DN=self.DN, settings=settings)

    def create_child(self, settings, DN=None, rdn=None, extras={}):
        if rdn is None:
            if 'host_names' in extras:
                rdn = "CN={0}".format(extras['host_names'][0])
            elif 'user_emails' in extras:
                rdn = "CN={0}".format(extras['user_emails'][0])

        if DN is None:
            if rdn is None:
                raise ValueError
            else:
                if self.base_dn:
                    DN = "{0}, {1}".format(rdn, self.base_dn)
                else:
                    DN = rdn

        extras['serial_number'] = self.get_next_serial_number()

        return Certificate.create(DN=DN, settings=settings, sign_ca=self.certificate, **extras)

class UserType(Enum):
    USER = "user"
    ADMIN = "admin"

DEFAULT_CONFIGURATION = """
leftsubnet=0.0.0.0/0
rightsourceip=%dhcp
keyexchange=ikev2
ike=aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024! # Win7 is aes256, sha-1, modp1024; iOS is aes256, sha-256, modp1024; OS X is 3DES, sha-1, modp1024
esp=aes256-sha256,aes256-sha1,3des-sha1! # Win 7 is aes256-sha1, iOS is aes256-sha256, OS X is 3des-shal1
"""

class VPNServer(db.Model, CRUDMixin):
    __tablename__ = "vpn_server"
    id = db.Column(GUID, primary_key=True, default=uuid4)
    name = db.Column(db.String(255))
    
    external_hostname = db.Column(db.String(255))
    psk = db.Column(db.String(255))

    certificate_id = db.Column('certificate_id', GUID, db.ForeignKey('certificate.id'))
    certificate = db.relationship('Certificate')

    base_dns_name = db.Column(db.String(255))

    configuration = db.Column(db.Text())

    CAs = db.relationship(
        "CertificateAuthority",
        secondary=ca_vpn_table,
        back_populates="VPNs")

    def __init__(self, name, external_hostname, base_dns_name=None, psk=Ellipsis, certificate=Ellipsis, configuration=DEFAULT_CONFIGURATION, CAs=None, CA_params={}, certificate_params={}):
        self.name = name
        self.external_hostname = external_hostname
        self.configuration = configuration

        if base_dns_name is None:
            if '.' in self.external_hostname:
                host_prefix, self.base_dns_name = self.external_hostname.split('.', 1)
            else:
                raise ValueError
        else:
            self.base_dns_name = base_dns_name
        
        if psk is Ellipsis:
            self.psk = pwd.genword(entropy=current_app.config["PSK_ENTROPY"])
        else:
            self.psk = psk
        
        if CAs is None:
            CA_params = dict(CA_params)
            CA_params.setdefault("rdn", "CN={0}".format("VPN CA 1"))
            ca = CertificateAuthority.create(**CA_params)
            self.CAs.append(ca)
        else:
            self.CAs.extend(CAs)

        if certificate is Ellipsis:
            if len(self.CAs):
                certificate_params = dict(certificate_params)
                certificate_params.setdefault('settings', CERTIFICATE_SETTINGS_IPSEC_SERVER)
                certificate_params.setdefault('extras', {
                }).setdefault('host_names', [self.external_hostname])
                self.certificate = self.CAs[0].create_child(**certificate_params)
        else:
            self.certificate = certificate

    def find_user(self, user):
        for vu in self.users:
            if vu.user == user:
                return vu
        return None

    def add_user(self, user, user_type=UserType.USER):
        vu = self.find_user(user)
        if vu:
            if vu.user_type == user_type:
                current_app.logger.debug("Not adding {0} with type {1} to {2}, already existing".format(user, user_type, self))
            else:
                vu.set_user_type(user_type)

            return vu

        vu = VPNUser.create(vpn_server=self, user_type=user_type, user=user)
        self.users.append( vu )
        return vu

    def get_signing_ca(self):
        return self.CAs[0] # FIXME

## FIXME Uniqueness-Constraints in all classes

class VPNUser(db.Model, CRUDMixin):
    __tablename__ = 'vpn_user'
    id = db.Column(GUID, primary_key=True, default=uuid4)

    vpn_server_id = db.Column('vpn_server_id', GUID, db.ForeignKey('vpn_server.id'))
    vpn_server = db.relationship('VPNServer', backref=db.backref('users', lazy='dynamic'))

    user_type = db.Column(db.Enum(UserType), default=UserType.USER)      

    user_id = db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('vpns', lazy='dynamic'))

    def set_user_type(self, user_type):
        self.user_type = user_type
        current_app.logger.debug("Changing {0} to type {1} in {2}".format(self.user, user_type, self.vpn_server))
        self.save()

    def add_device(self, device_type, **params):
        if issubclass(device_type.__class__, type) and issubclass(device_type, DeviceBase):
            device_class = device_type
        else:
            device_class = DeviceBase.class_from_type(device_type)

        d = device_class.create(vpn_user=self, **params)
        current_app.logger.debug("Added {0} to {1}".format(d, self))
        self.save()

        return d

class DeviceBase(db.Model, CRUDMixin):
    __tablename__ = 'device'
    DEVICE_TYPE = None

    id = db.Column(GUID, primary_key=True, default=uuid4)
    name = db.Column(db.String(255))
    device_type = db.Column(db.String())

    @declared_attr
    def __mapper_args__(cls):
        return {
            'polymorphic_on': cls.device_type,
            'polymorphic_identity': cls.DEVICE_TYPE,
        }

    vpn_user_id = db.Column('vpn_user_id', GUID, db.ForeignKey('vpn_user.id'))
    vpn_user = db.relationship('VPNUser', backref=db.backref('devices', lazy='dynamic'))

    @classmethod
    def all_subclasses(cls):
        yield cls
        for subcls in cls.__subclasses__():
            yield from subcls.all_subclasses()

    @classmethod
    def class_from_type(cls, device_type):
        for subcls in cls.all_subclasses():
            if subcls.DEVICE_TYPE == device_type:
                return subcls
        return None

    @staticmethod
    def nameify(name):
        # 1 Collapse all whitespace
        name = "_".join(name.split())
        # 2 Lowercase
        name = name.lower()
        # 3 Remove all characters that are not lowercase/digits/_
        name = "".join(e for e in name if e in ascii_lowercase+digits+'_')
        return name

class GenericPskXauthDevice(DeviceBase):
    "Generic (PSK/XAUTH)"
    DEVICE_TYPE = "generic_psk_xauth"

    device_identity = db.Column(db.String(255))
    password = db.Column(db.String(255))

    def __init__(self, password=None, device_identity=None, **kwargs):
        super(GenericPskXauthDevice, self).__init__(**kwargs)
        if device_identity is None:
            if 'vpn_user' in kwargs and 'name' in kwargs:
                self.device_identity = "{0}_{1}".format(kwargs['vpn_user'].user.email, self.nameify(kwargs['name']))
            else:
                raise ValueError
        else:
            self.device_identity = device_identity
        if password is None:
            self.password = pwd.genword(entropy=current_app.config["PSK_ENTROPY"])
        else:
            self.password = password

class GenericUserCertificateDevice(DeviceBase):
    "Generic (User Certificate)"
    DEVICE_TYPE = "generic_user_certificate"

    certificate_id = db.Column('certificate_id', GUID, db.ForeignKey('certificate.id'))
    certificate = db.relationship('Certificate')

    def __init__(self, certificate=None, **kwargs):
        super(GenericUserCertificateDevice, self).__init__(**kwargs)

        CA = kwargs['vpn_user'].vpn_server.get_signing_ca()

        if certificate is None:
            certificate_params = dict()
            certificate_params.setdefault('DN', 'CN={0}'.format(kwargs['vpn_user'].user.email))
            certificate_params.setdefault('settings', CERTIFICATE_SETTINGS_IPSEC_DEVICE)
            certificate_params.setdefault('extras', {
            }).setdefault('user_emails', [kwargs['vpn_user'].user.email])
            self.certificate = CA.create_child(**certificate_params)
        else:
            self.certificate = certificate

class AndroidNativeDevice(GenericPskXauthDevice):
    "Android (4.4+, native client)"
    DEVICE_TYPE = "android_native"

class AndroidStrongswanDevice(GenericUserCertificateDevice):
    "Android (4.4+, StrongS/WAN client)"
    DEVICE_TYPE = "android_strongswan"

class Ios10Device(GenericUserCertificateDevice):
    "iOS 10+, OS X 10.11+"
    DEVICE_TYPE = "ios_10"

class Win10Device(GenericUserCertificateDevice):
    "Windows 10+"
    DEVICE_TYPE = "win_10"

class GenericLinuxDevice(GenericUserCertificateDevice):
    "Linux (generic)"
    DEVICE_TYPE = "linux"

class LinuxDebDevice(GenericLinuxDevice):
    "Linux .deb based (Ubuntu, Debian, Mate)"
    DEVICE_TYPE = "linux_deb"

class LinuxRpmDevice(GenericLinuxDevice):
    "Linux .rpm based (Fedora, RedHat, CentOS)"
    DEVICE_TYPE = "linux_rpm"

