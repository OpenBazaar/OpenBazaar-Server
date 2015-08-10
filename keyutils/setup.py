__author__ = 'chris'
from distutils.core import setup, Extension

setup(name='guidc', version='0.0',
      ext_modules=[Extension('guidc', sources=['guidc.c'], libraries=['sodium'])])
