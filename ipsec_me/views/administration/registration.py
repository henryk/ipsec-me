# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

from flask_security import ConfirmRegisterForm
from flask_wtf.recaptcha import RecaptchaField


class ExtendedRegisterForm(ConfirmRegisterForm):
    recaptcha = RecaptchaField()

    def validate(self):
        rv = ConfirmRegisterForm.validate(self)
        if not rv:
            return False

        return True
