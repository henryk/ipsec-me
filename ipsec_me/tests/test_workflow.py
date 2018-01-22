# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

from nose.plugins.attrib import attr
from ..models import User, VPNServer
from .mixins import DiamondTestCase
from .fixtures import typical_workflow


class WorkflowTestCase(DiamondTestCase):
    def setUp(self):
        super(WorkflowTestCase, self).setUp()
        typical_workflow()

    def test_user(self):
        "user created in workflow"
        u = User.find(email='guest@example.com')
        assert u
        assert u.email == 'guest@example.com'

    @attr("single")
    def test_vpn_create(self):
        "create vpn"
        v = VPNServer.query.first()
        a = v.CAs[0]
        assert a
        assert a.certificate
        assert a.certificate.private_key
        assert a.certificate.certificate

    def test_device_create(self):
        "create device"
        u = User.find(email='guest@example.com')
        v = u.vpns[0].vpn_server

        vu = v.find_user(u)
        assert vu
        d = vu.add_device(name="Fnord", device_type="android_native")
        assert d
        assert d.password

    def test_device_certificate(self):
        "create device with certificate"
        u = User.find(email='guest@example.com')
        v = u.vpns[0].vpn_server

        vu = v.find_user(u)
        d = vu.add_device(name="Fnord", device_type="generic_user_certificate")
        assert d.certificate
        assert d.certificate.certificate
        assert d.certificate.private_key

