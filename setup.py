# -*- coding: utf-8 -*-
# ipsec-me (c) Henryk Plötz

import re
import os
import codecs
from setuptools import setup, find_packages
from distutils.dir_util import copy_tree


def read(*rnames):
    return codecs.open(os.path.join(os.path.dirname(__file__), *rnames), 'r', 'utf-8').read()


def grep(attrname):
    pattern = r"{0}\W*=\W*'([^']+)'".format(attrname)
    strval, = re.findall(pattern, read('ipsec_me/__meta__.py'))
    return strval


setup(
    version=grep('__version__'),
    name='ipsec-me',
    description="IPsec Made Easy helps with deploying IPsec VPN profiles",
    packages=find_packages(),
    scripts=[
        "bin/runserver.py",
        "bin/manage.py",
    ],
    long_description=read('Readme.rst'),
    classifiers=[],  # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    include_package_data=True,
    keywords='',
    author=grep('__author__'),
    author_email=grep('__email__'),
    url=grep('__url__'),
    install_requires=read('requirements.txt'),
    license='MIT',
    zip_safe=False,
)
