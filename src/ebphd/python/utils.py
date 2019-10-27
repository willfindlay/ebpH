# ebpH --  An eBPF intrusion detection program.
# -------  Monitors system call patterns and detect anomalies.
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
# Anil Somayaji (soma@scs.carleton.ca)
#
# Based on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# USAGE: ebphd <COMMAND>
#
# Licensed under GPL v2 License

import os, sys

from config import Config

def path(f):
    curr_dir = os.path.realpath(os.path.dirname(__file__))
    project_dir = os.path.realpath(os.path.join(curr_dir,"../../.."))
    path = os.path.realpath(os.path.join(project_dir, f))
    return path
