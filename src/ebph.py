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
from http import HTTPStatus as Status

import config
import json
from utils import to_json_bytes, from_json_bytes, receive_message, send_message

def print_profile_information(v, header=0):
    comm = v["comm"] if len(v["comm"]) < 32 else ''.join([v["comm"][:(32-3)], '...'])
    status = 'Frozen' if v["frozen"] and not v["normal"] else 'Normal' if v["normal"] else 'Training'

    if header:
        print(f"%12s %-32s %-12s %-12s %-12s %-12s" % ('KEY', 'COMM', 'STATUS', 'COUNT', 'LAST_MOD', 'ANOMALIES'))

    print(f"%12d %-32s %-12s %-12d %-12s %-12d" % (v["key"], comm, status, v["train_count"],
        v["last_mod_count"], v["anomalies"]))

def print_process_information(v, header=0):
    if header:
        print(f"%-12s %-12s %-12s %-12s %-12s %-12s" % ('PID', 'COMM', 'STATUS', 'COUNT', 'LAST_MOD', 'ANOMALIES'))

    p = v["profile"]
    comm = p["comm"] if len(p["comm"]) < 32 else ''.join([p["comm"][:(32-3)], '...'])
    status = 'Frozen' if p["frozen"] and not p["normal"] else 'Normal' if p["normal"] else 'Training'

    print(f"%-12d %-12s %-12s %-12d %-12s %-12d" % (v["pid"], comm, status, p["train_count"],
        p["last_mod_count"], p["anomalies"]))


if __name__ == "__main__":
    OPERATIONS=['stop_monitoring', 'start_monitoring', 'save_profiles', 'fetch_profile', 'fetch_process', 'fetch_all_profiles', 'fetch_all_processes']

    def parse_args(args=[]):
        parser = argparse.ArgumentParser(description="Command script for ebpH.", prog="ebph", epilog="Configuration file is located in config.py",
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

    args = parse_args(sys.argv[1:])
    config.init()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(config.socket)

    # Form request
    request = {'func': args.operation, 'args': args.args, 'kwargs': None}

    # Send request
    send_message(sock, to_json_bytes(request))

    # Handle response
    res = receive_message(sock)
    res = from_json_bytes(res)

    if args.operation == 'fetch_all_profiles':
        header = 1
        for k, v in sorted(res['message'].items(), key = lambda item: item[1]["comm"]):
            print_profile_information(v, header)
            header = 0

    if args.operation == 'fetch_all_processes':
        header = 1
        for k, v in sorted(res['message'].items(), key = lambda item: item[1]["pid"]):
            print_process_information(v, header)
            header = 0

    sock.close()
