#! /usr/bin/env python3

import os, sys
import socket
import argparse
import struct

import config
import json
from utils import to_json_bytes, from_json_bytes, receive_message, send_message

DESCRIPTION = """
List processes/profiles being traced by ebpH.
The ebpH daemon must be running in order to run this software.
"""

EPILOG = """
"""

def format_comm(comm):
    return comm if len(comm) < 16 else ''.join([comm[:(16-3)], '...'])

def print_profile_information(profile, header=0):
    comm = format_comm(profile["comm"])
    status = 'Frozen' if profile["frozen"] else 'Normal' if profile["normal"] else 'Training'

    if header:
        print(f"{'KEY':<12} {'COMM':<16} {'STATUS':<12} {'TRAIN_COUNT':<12} {'LAST_MOD':<12} {'ANOMALIES':<12}")

    print(f"{profile['key']:<12} {comm:<16} {status:<12} {profile['train_count']:<12} {profile['last_mod_count']:<12} "
          f"{profile['anomalies']:<12}")

def print_process_information(process, header=0, show_threads=0):
    profile = process["profile"]
    comm = format_comm(profile["comm"])
    status = 'Frozen' if profile["frozen"] else 'Normal' if profile["normal"] else 'Training'

    if header and show_threads:
        print(f"{'PID':<8} {'TID':<8} {'COMM':<16} {'STATUS':<12} {'TRAIN_COUNT':<12} {'LAST_MOD':<12} {'ANOMALIES':<12}")
    elif header:
        print(f"{'PID':<8} {'COMM':<16} {'STATUS':<12} {'COUNT':<12} {'LAST_MOD':<12} {'ANOMALIES':<12}")

    if show_threads:
        print(f"{process['pid']:<8} {process['tid']:<8} {comm:<16} {status:<12} {profile['train_count']:<12} {profile['last_mod_count']:<12} "
              f"{profile['anomalies']:<12}")
    else:
        print(f"{process['pid']:<8} {comm:<16} {status:<12} {profile['train_count']:<12} {profile['last_mod_count']:<12} "
              f"{profile['anomalies']:<12}")

def sort_key(args):
    if args.profiles:
        return lambda item: item[1]["comm"]
    elif args.threads:
        return lambda item: (item[1]["pid"], item[1]["tid"])
    else:
        return lambda item: item[1]["pid"]

def parse_args(args=[]):
    parser = argparse.ArgumentParser(description=DESCRIPTION, prog="ebph-ps", epilog=EPILOG,
            formatter_class=argparse.RawTextHelpFormatter)

    options = parser.add_mutually_exclusive_group()
    options.add_argument('-t', '--threads', action='store_true',
            help=f"Print all threads instead of just thread group leader.")
    options.add_argument('-p', '--profiles', action='store_true',
            help=f"Print all profiles instead of active processes.")

    args = parser.parse_args(args)

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
    request = {'func': 'fetch_profiles' if args.profiles else 'fetch_processes'}

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
