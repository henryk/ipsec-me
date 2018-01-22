# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

from flask_diamond import Diamond
from flask_diamond.facets.administration import AdminModelView
from flask_diamond.facets.database import db
from .models import User, Role, VPNServer, CertificateAuthority, VPNUser, GenericPskXauthDevice, GenericUserCertificateDevice
from .config import DefaultConfig

# declare these globalish objects before initializing models
application = None


class ipsec_me(Diamond):
    def init_configuration(self):
        """
        Load the application configuration from the ``SETTINGS`` environment variable.

        :returns: None

        ``SETTINGS`` must contain a filename that points to the configuration file.
        """

        self.app.config.from_object('ipsec_me.DefaultConfig')
        self.app.config.from_envvar('SETTINGS')

    def init_accounts(self):
        "initialize accounts with the User and Role classes imported from .models"
        return self.super("accounts", user=User, role=Role)

    def init_administration(self):
        "Initialize admin interface"

        admin = self.super("administration", user=User, role=Role)

        model_list = [
            VPNServer,
            CertificateAuthority,
            VPNUser,
            GenericPskXauthDevice,
            GenericUserCertificateDevice
        ]

        for model in model_list:
            admin.add_view(AdminModelView(
                model,
                db.session,
                name=model.__name__,
                category="Models")
            )

        return admin

    def init_blueprints(self):
        "Application blueprints"

        self.super("blueprints")

        # administration blueprint is custom to this application
        from .views.administration.modelviews import adminbaseview
        self.app.register_blueprint(adminbaseview)

        from .views.diamond import diamond_blueprint
        self.app.register_blueprint(diamond_blueprint)


def create_app():
    global application
    if not application:
        application = ipsec_me()
        application.facet("configuration")
        application.facet("logs")
        application.facet("database")
        application.facet("marshalling")
        application.facet("blueprints")
        application.facet("accounts")
        application.facet("signals")
        application.facet("forms")
        application.facet("error_handlers")
        application.facet("request_handlers")
        application.facet("administration")
        # application.facet("rest", api_map=api_map)
        # application.facet("webassets")
        # application.facet("email")
        application.facet("debugger")
        # application.facet("task_queue")

    # print application.app.url_map
    return application.app
