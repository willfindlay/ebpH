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

OPERATIONS=['stop_monitoring', 'start_monitoring', 'save_profiles', 'fetch_profiles', 'fetch_processes']

DESCRIPTION = """
List processes/profiles being traced by ebpH.
The ebpH daemon must be running in order to run this software.
"""

EPILOG = """
"""

def command_argument(s):
    """
    Command argument type for argparse.
    """
    pass

def parse_args(args=[]):
    parser = argparse.ArgumentParser(description=DESCRIPTION, prog="ebph-admin", epilog="Configuration file is located in config.py",
            formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('operation', metavar="Operation", type=lambda s: str(s).lower(), choices=OPERATIONS,
            help=f"Operation you want to perform. Choices are: {', '.join(OPERATIONS)}.")
    parser.add_argument('-v', dest='verbose', action='store_true',
            help=f"Print verbose output.")
    parser.add_argument('args', metavar="Command Arguments", type=lambda s: ast.literal_eval(s), nargs='*',
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

    items = sorted(res['message'].items(), key=sort_key(args))

    if not args.profiles and not args.threads:
        items = [(k, v) for k, v in items if v["pid"] == v["tid"]]

    # Print output
    header = 1
    for k, v in items:
        if args.profiles:
            print_profile_information(v, header)
        else:
            print_process_information(v, header, args.threads)
        header = 0
    sock.close()
