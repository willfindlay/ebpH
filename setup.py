#!/usr/bin/env python3

import os, sys
import re
from distutils.core import setup

with open('README.md', 'r') as f:
    try:
        version = re.match(r'\#\s+ebpH\s+v(\d+\.\d+\.\d+)', f.readline())[1]
    except:
        version = 'unknown'

setup(name='ebpH',
      version=version,
      description='Extended BPF Process Homeostasis: Host-based anomaly detection in eBPF',
      author='William Findlay',
      author_email='william.findlay@carleton.ca',
      url='https://github.com/willfindlay/ebpH',
      packages=['ebpH'],
      include_package_data=True,
     )
