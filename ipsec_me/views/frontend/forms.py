from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class NewDeviceForm(FlaskForm):
	name = StringField('Device name', validators=[DataRequired()])
	create = SubmitField('Create!')
