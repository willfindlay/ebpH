#!/usr/bin/env python3

"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    Copyright (C) 2019-2020  William Findlay

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    2020-Jul-13  William Findlay  Created this.
"""

import os, sys
import re
from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext

version = '0.2.2'


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


libebph = CTypes('ebph/libebph/bin/libebph', sources=['ebph/libebph/libebph.c'])


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
    package_data={'': ['ebph/bpf/*', 'ebph/libebph/*', 'ebph/commands/*']},
    ext_modules=[libebph],
    cmdclass={'build_ext': ct_build_ext},
)
