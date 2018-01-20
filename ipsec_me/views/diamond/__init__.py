# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

import flask

diamond_blueprint = flask.Blueprint(
    'diamond_blueprint',
    __name__,
    static_folder='static',
    template_folder='templates',
    static_url_path='/static/diamond',
)
