__author__ = 'chris'

# pylint: disable=E0611,F0401
#         No name 'core' in module 'distutils'
#         Unable to import 'distutils.core'
from distutils.core import setup, Extension

setup(name='guidc', version='0.0',
      ext_modules=[Extension('guidc', sources=['guidc.c'], libraries=['sodium'])])
