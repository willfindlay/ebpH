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
import logging

import utils

# Location where socket and pidfile should be stored
socketdir = '/run'

# Location where log files should be saved
logdir = '/var/log/ebpH'

# ebpH data directory
# WARNING: Don't pick a directory you're already using
#          The permissions will be changed
ebph_data_dir =  '/var/lib/ebpH'

# Verbosity level for logging
# Possible values: logging.CRITICAL, logging.ERROR, logging.WARNING,
#                  logging.INFO,     logging.DEBUG
verbosity = logging.INFO

# How long ebpH should sleep between ticks in seconds?
# Lower values imply higher CPU usage
# Recommended value is around 1 second
ticksleep = 0.1

# How many ticks between automatic saves
saveinterval = 6000 # about 10 minutes

# When attempting to stop the daemon, how long do we wait before giving up?
killtimeout = 20

# Size of socket messages
socket_buff_size = 3

# Sentinel value for ending socket messages
# Defaults to the null character
socket_sentinel = b"\x00"

def init():
    # Project path
    global project_path
    project_path = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))

    # Set profiles dir
    global profiles_dir
    profiles_dir = os.path.join(ebph_data_dir, 'profiles')

    # BPF C file location
    global bpf_program
    bpf_program = utils.path('src/bpf/bpf_program.c')

    # Configure file locations
    global socket
    socket = os.path.join(socketdir, 'ebph.sock')
    global pidfile
    pidfile = os.path.join(socketdir, 'ebph.pid')
    global logfile
    logfile = os.path.join(logdir, 'ebph.log')
