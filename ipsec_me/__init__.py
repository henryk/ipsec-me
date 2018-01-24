# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

from flask_diamond import Diamond
from flask_diamond.facets.administration import AdminModelView
from flask_diamond.facets.database import db
from flask_bootstrap import Bootstrap
from flask_babel import Babel
from flask_qrcode import QRcode
from werkzeug.routing import BaseConverter, NotFound
from itsdangerous import Signer, BadData
from hmac import compare_digest
from .models import User, Role, VPNServer, CertificateAuthority, DeviceBase, VPNUser, GenericPskXauthDevice, GenericUserCertificateDevice
from .config import DefaultConfig

# declare these globalish objects before initializing models
application = None


class VPNServerConverter(BaseConverter):
    def to_url(self, value):
        return str(value.id)

    def to_python(self, value):
        retval = VPNServer.find(id=str(value))
        if retval is None:
            raise NotFound
        return retval

class DeviceClassConverter(BaseConverter):
    def to_url(self, value):
        return str(value.DEVICE_TYPE)

    def to_python(self, value):
        retval = DeviceBase.class_from_type(str(value))
        if retval is None:
            raise NotFound
        return retval

class DeviceConverter(BaseConverter):
    def to_url(self, value):
        return str(value.id)

    def to_python(self, value):
        retval = DeviceBase.find(id=str(value))
        if retval is None:
            raise NotFound
        return retval

class DeviceSecureConverter(BaseConverter):
    def to_url(self, value):
        result = "{0}.{1}".format( str(value.id), value.certificate.get_hexhash() ).encode("US-ASCII")
        return Signer(application.app.secret_key, salt=b'device-secure').sign(result).decode("US-ASCII")


    def to_python(self, value):
        try:
            data = Signer(application.app.secret_key, salt=b'device-secure').unsign(value)
        except BadData:
            raise NotFound
        device_id, certificate_hash = data.decode("US-ASCII").split('.', 2)
        retval = DeviceBase.find(id=str(device_id))
        if retval is None:
            raise NotFound
        if not compare_digest(certificate_hash, retval.certificate.get_hexhash()):
            raise NotFound
        return retval

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

        from .views.frontend import frontend_blueprint
        self.app.register_blueprint(frontend_blueprint)

    def init_request_handlers(self): pass


def create_app():
    global application
    if not application:
        application = ipsec_me()

        application.app.url_map.converters['vpn_server'] = VPNServerConverter
        application.app.url_map.converters['device_class'] = DeviceClassConverter
        application.app.url_map.converters['device'] = DeviceConverter
        application.app.url_map.converters['device_secure'] = DeviceSecureConverter

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

        Bootstrap(application.app)
        Babel(application.app)
        QRcode(application.app)

    # print application.app.url_map
    return application.app
