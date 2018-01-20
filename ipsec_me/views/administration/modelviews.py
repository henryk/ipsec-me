# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

import flask
import flask_security as security
from flask_admin import expose
from flask_diamond import db
from flask_diamond.facets.administration import AuthModelView, AdminIndexView


adminbaseview = flask.Blueprint('adminbaseview', __name__,
    template_folder='templates', static_folder='static')


class RedirectView(AdminIndexView):
    def is_visible(self):
        return False

    def is_accessible(self):
        return security.current_user.is_authenticated()

    @expose('/')
    def index(self):
        return flask.redirect(flask.url_for('user.list_view'))
