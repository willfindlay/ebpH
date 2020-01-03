#! /usr/bin/env python3

# ebpH --  An eBPF intrusion detection program.
# -------  Monitors system call patterns and detect anomalies.
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
# Anil Somayaji (soma@scs.carleton.ca)
#
# Based on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# USAGE: ebph <COMMAND>
#
# Licensed under GPL v2 License

import os, sys
import socket
import argparse
import struct
from http import HTTPStatus as Status

import config
from utils import to_json_bytes, from_json_bytes

if __name__ == "__main__":
    OPERATIONS=['stop_monitoring', 'start_monitoring', 'save_profiles']

    def parse_args(args=[]):
        parser = argparse.ArgumentParser(description="Command script for ebpH.", prog="ebph", epilog="Configuration file is located in config.py",
                formatter_class=argparse.RawTextHelpFormatter)

        parser.add_argument('operation', metavar="Operation", type=lambda s: str(s).lower(), choices=OPERATIONS, nargs='?',
                help=f"Operation you want to perform. Choices are: {', '.join(OPERATIONS)}.")
        parser.add_argument('-v', dest='verbose', action='store_true',
                help=f"Print verbose output.")

        args = parser.parse_args(args)

        if not args.operation:
            parser.error("Please specify an operation")

        # check for root
        if not (os.geteuid() == 0):
            parser.error("This script must be run with root privileges! Exiting.")

        return args

    args = parse_args(sys.argv[1:])
    config.init()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(config.socket)

    # Form request
    request = {'func': args.operation, 'args': None, 'kwargs': None}

    # Send request
    sock.send(to_json_bytes(request))

    # Handle response
    res = sock.recv(config.socket_buff_size)
    res = from_json_bytes(res)
    print(res)
    sock.close()
