# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

from nose.plugins.attrib import attr
from ..models import User
from .mixins import DiamondTestCase


class UserTestCase(DiamondTestCase):
    "Coverage for User Model"

    def test_create(self):
        "ensure an account can be created"
        User.create(email='guest@example.com', password='a_password')
        an_account = User.find(email='guest@example.com')
        assert an_account
        assert an_account.email == 'guest@example.com'
