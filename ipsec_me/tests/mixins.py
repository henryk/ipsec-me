# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

from flask import current_app
from .. import create_app, db
from flask_testing import TestCase


class DiamondTestCase(TestCase):
    def create_app(self):
        """
        Create a Flask-Diamond app for testing.
        """

        app = create_app()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        return app

    def setUp(self):
        """
        Prepare for a test case.
        """

        db.create_all()
        current_app.logger.debug("setup complete")

    def tearDown(self):
        """
        Clean up after a test case.
        """

        db.session.remove()
        db.drop_all()
