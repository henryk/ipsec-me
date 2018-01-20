#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

from ipsec_me.wsgi import app
app.run(port=app.config['PORT'])
