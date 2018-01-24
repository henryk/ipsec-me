# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

class DefaultConfig(object):
	RSA_KEYSIZE = 4096
	PSK_ENTROPY = 96

	BOOTSTRAP_SERVE_LOCAL = True

## HACK HACK
import os
if os.environ.get("SILENCE_DEPRECATION", 0):
    import warnings
    warnings.filterwarnings('ignore', category=DeprecationWarning)


