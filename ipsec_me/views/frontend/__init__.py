# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

import flask
from flask_security import login_required, current_user
from ...models import DeviceBase
from .forms import NewDeviceForm

from jinja2.exceptions import TemplateNotFound
from uuid import uuid4
from base64 import b64encode
from passlib import pwd

frontend_blueprint = flask.Blueprint(
    'frontend_blueprint',
    __name__,
    static_folder='static',
    template_folder='templates',
    static_url_path='/static/frontend',
)

@frontend_blueprint.route('/')
@login_required
def index():
	return flask.render_template('frontend/index.html')

@frontend_blueprint.route('/vpn/<vpn_server:vpn_server>/add_device')
@frontend_blueprint.route('/vpn/<vpn_server:vpn_server>/add_device/<device_class:device_class>', methods=['GET', 'POST', 'OPTIONS', 'HEAD'])
@login_required
def vpn_add_device(vpn_server, device_class=None):
	if device_class is None:
		return flask.render_template('frontend/choose_device_type.html', vpn_server=vpn_server, DeviceBase=DeviceBase)

	else:
		form = NewDeviceForm()
		if form.validate_on_submit():
			vu = vpn_server.find_user(current_user)
			d = vu.add_device(name=form.name.data, device_type=device_class)
			return flask.redirect(flask.url_for('.device_show', vpn_server=vpn_server, device=d))

		return flask.render_template('frontend/vpn_add_device.html', form=form, vpn_server=vpn_server, device_class=device_class)

@frontend_blueprint.route('/vpn/<vpn_server:vpn_server>/device/<device:device>')
@login_required
def device_show(vpn_server, device):
	if not device.vpn_user.vpn_server is vpn_server:
		flask.abort(404)

	if not device.vpn_user.user.id == current_user.id: ## FIXME Admin access
		flask.abort(404)

	for cls in type(device).mro():
		if issubclass(cls, DeviceBase):
			try:
				return flask.render_template('frontend/devices/{0}.html'.format(cls.__name__), device=device, vpn_server=vpn_server)
			except TemplateNotFound:
				flask.current_app.logger.warn("Trying to access device setup page for %s which doesn't exist", cls.__name__)


	flask.abort(500)

@frontend_blueprint.route('/provision/generic/<device_secure:device>.p12')
def device_generic_pkcs12(device):
	return flask.Response(response=device.certificate.get_pkcs12(include_chain=False), mimetype='application/x-pkcs12')
	
@frontend_blueprint.route('/provision/generic/<device_secure:device>_ca.pem')
def device_generic_ca(device):
	return flask.Response(response=device.certificate.get_ca_pem(), mimetype='application/x-pem-file')
	
@frontend_blueprint.route('/provision/generic/<device_secure:device>_cert.pem')
def device_generic_cert(device):
	return flask.Response(response=device.certificate.get_cert_pem(), mimetype='application/x-pem-file')
	
@frontend_blueprint.route('/provision/generic/<device_secure:device>_key.pem')
def device_generic_key(device):
	return flask.Response(response=device.certificate.get_key_pem(), mimetype='application/x-pem-file')
	

@frontend_blueprint.route('/provision/android_strongswan/<device_secure:device>.sswan')
def device_android_strongswan_profile(device):
	response = {
		'uuid': str(device.id),
		'name': device.vpn_user.vpn_server.name,
		'type': 'ikev2-cert',
		'remote': {
			'addr': device.vpn_user.vpn_server.external_hostname,
			'cert': b64encode(device.vpn_user.vpn_server.certificate.certificate).decode("US-ASCII"), ## FIXME Proper CA
		},
		'local': {
			'p12': b64encode(device.certificate.get_pkcs12(include_chain=False)).decode("US-ASCII"),
		},
	}
	return flask.Response(response=flask.json.dumps(response), mimetype='application/vnd.strongswan.profile')

@frontend_blueprint.route('/provision/ios10/<device_secure:device>.mobileconfig')
def device_ios10_profile(device):
	password = pwd.genword()
	return flask.Response(
		response=flask.render_template('frontend/devices/ios10_profile.xml', 
			device=device,
			b64encode=lambda s: b64encode(s).decode('US-ASCII'),
			password=password), 
		mimetype='application/octet-stream')
		#mimetype='text/xml')
