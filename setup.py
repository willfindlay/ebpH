#!/usr/bin/env python3

import os, sys
import re
from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext

version = '0.2.0'


class ct_build_ext(build_ext):
    def build_extension(self, ext):
        self._ctypes = isinstance(ext, CTypes)
        return super().build_extension(ext)

    def get_export_symbols(self, ext):
        if self._ctypes:
            return ext.export_symbols
        return super().get_export_symbols(ext)

    def get_ext_filename(self, ext_name):
        if self._ctypes:
            return ext_name + '.so'
        return super().get_ext_filename(ext_name)


class CTypes(Extension):
    pass


libebph = CTypes('ebph/libebph/bin/libebph', sources=['ebph/libebph/libebph.c'], library_dirs=['/usr/local/lib'])


setup(
    name='ebph',
    version=version,
    description='Extended BPF Process Homeostasis: Host-based anomaly detection in eBPF.',
    author='William Findlay',
    author_email='william@williamfindlay.com',
    url='https://github.com/willfindlay/ebpH',
    packages=['ebph'],
    scripts=['bin/ebphd', 'bin/ebph'],
    include_package_data=True,
    ext_modules=[libebph],
    cmdclass={'build_ext': ct_build_ext},
)
