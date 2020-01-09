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
import ast
import socket
import argparse
import struct

import config
import json
from utils import to_json_bytes, from_json_bytes, receive_message, send_message

DESCRIPTION = """
Issue commands to ebpH and make queries about system state.
The ebpH daemon (ebphd) must be running in order to run this software.
"""

EPILOG = """
Example usage:
    sudo ebph-admin
"""

def command_argument(s):
    """
    Command argument type for argparse.
    """
    pass

def parse_args(args=[]):
    parser = argparse.ArgumentParser(description=DESCRIPTION, prog="ebph-admin", epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('operation', metavar="Operation", type=lambda s: str(s).lower(), choices=OPERATIONS,
            help=f"Operation you want to perform. Choices are: %(choices)s.")
    parser.add_argument('-v', dest='verbose', action='store_true',
            help=f"Print verbose output.")
    parser.add_argument('args', metavar="Command Arguments", nargs='*',
            help=f"Arguments to the specified command")

    args = parser.parse_args(args)

    if not args.operation:
        parser.error("Please specify an operation")

    # check for root
    if not (os.geteuid() == 0):
        parser.error("This script must be run with root privileges! Exiting.")

    return args

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    config.init()

    print(args.args)

    # Connect to socket
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(config.socket)
    except ConnectionRefusedError:
        print(f"Unable to connect to {config.socket}... Is ebphd running?", file=sys.stderr)

    # Form request
    request = {'func': args.operation, 'args': args.args}

    # Send request
    send_message(sock, to_json_bytes(request))

    # Handle response
    res = receive_message(sock)
    res = from_json_bytes(res)
