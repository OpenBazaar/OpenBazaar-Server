__author__ = 'chris'
from distutils.core import setup, Extension

setup(name='guid', version='0.0',
	ext_modules = [Extension('guid', sources=['guid.c'], libraries=['sodium'])])