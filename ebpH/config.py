# ebpH  An eBPF intrusion detection program. Monitors system call patterns and detect anomalies.
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
# Anil Somayaji (soma@scs.carleton.ca)
#
# Based on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# Licensed under GPL v2 License

import os, sys
import re
import datetime

from ebpH import utils

import configparser

config = configparser.ConfigParser()

# Locations that the config file can be in, falls back to default
config_locations = [
        utils.path('config/defaults.cfg'),
        '/etc/ebpH/ebpH.cfg',
        '/etc/ebpH/ebpH.conf',
        '/etc/ebpH/ebpH.ini',
        ]

# Read config files
config.read(config_locations)

time_regex = re.compile(r'((?P<weeks>\d+?)w)?((?P<days>\d+?)d)?((?P<hours>\d+?)hr?)'
                        r'?((?P<minutes>\d+?)m)?((?P<seconds>\d+?)s)?')
def parse_time(s):
    """
    Parse simple strings into seconds.
    """
    match = time_regex.match(s)
    if not match:
        return
    match = match.groupdict()
    time_params = {}
    for (name, param) in match.items():
        if param:
            time_params[name] = int(param)
    return datetime.timedelta(**time_params).total_seconds()
