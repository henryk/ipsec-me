# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

from nose.plugins.attrib import attr
from ..models import User
from .mixins import DiamondTestCase
from .fixtures import typical_workflow


class WorkflowTestCase(DiamondTestCase):
    def setUp(self):
        super(WorkflowTestCase, self).setUp()
        typical_workflow()

    @attr("single")
    def test_user(self):
        "user created in workflow"
        u = User.find(email='guest@example.com')
        assert u
        assert u.email == 'guest@example.com'
