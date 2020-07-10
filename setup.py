#!/usr/bin/env python3

import os, sys
import re
from distutils.core import setup

version = '0.2.1'

setup(name='ebph',
      version=version,
      description='Extended BPF Process Homeostasis: Host-based anomaly detection in eBPF',
      author='William Findlay',
      author_email='william@williamfindlay.com',
      url='https://github.com/willfindlay/ebpH',
      packages=['ebph'],
      include_package_data=True,
     )
