#! /usr/bin/env python3

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
import argparse
import time
import datetime
import signal

from structs import EBPHProfile
from utils import syscall_name, connect_to_socket, from_json_bytes, to_json_bytes, send_message, receive_message

import config
config.init()

signal.signal(signal.SIGPIPE, lambda x, y: sys.exit(0))

DESCRIPTION = """
Inspect individual ebpH profiles saved on disk.
Ordinarily, you will want to redirect output into a file like:
    sudo ebph-inspect -k 21342 > profile_21342_summary.txt
"""
# The ebpH daemon (ebphd) must be running in order to run this software.
# """

EPILOG = """
Example usage:
    sudo ebph-inspect -k 21342                   # Inspect profile with key 21342
    sudo ebph-inspect -p /tmp/testprofiles/21342 # Inspect profile stored in /tmp/testprofiles/21342
"""

#def fetch_profile_from_daemon():
#    # Connect to socket
#    sock = connect_to_socket()
#
#    # Form request
#    request = {'func': 'fetch_profile', 'args': []}
#
#    # Send request
#    send_message(sock, to_json_bytes(request))
#
#    # Handle response
#    res = receive_message(sock)
#    res = from_json_bytes(res)

def parse_profile(f):
    """
    Parse an EBPHProfile from a file.o

    Args:
        f: file

    Return:
        EBPHProfile
    """
    profile = EBPHProfile()
    f.readinto(profile)
    return profile

def print_profile_data(profile: EBPHProfile, data: 'train' or 'test', show_empty: bool):
    """
    Print training or testing profile data for an EBPHProfile

    Args:
        profile: EBPHProfile
        data: 'train' or 'test'
        show_empty: bool
    """
    # Make sure data is either train or test
    assert data == 'train' or data == 'test'
    # Set correct profile data according to specified data type
    profile_data = profile.train if data == 'train' else profile.test
    # Print correct header
    print()
    print('TRAINING DATA:' if data == 'train' else 'TESTING DATA:')
    print(f'{"CURR":>24} {"PREV":>24} {"":>10} FLAGS')
    # Print all entries
    for prev, row in enumerate(profile_data.flags):
        for curr, flag in enumerate(row):
            # Either ignore empty entries or show all
            if flag != 0 or show_empty:
                flag = bin(flag)[2:].zfill(8)
                print(f'{syscall_name(curr):>24} {syscall_name(prev):>24} {"":>10} {flag:>8}')

def print_profile(profile: EBPHProfile, show_empty: bool):
    """
    Print an EBPHProfile

    Args:
        profile: EBPHProfile
        show_empty: bool
    """
    # Format string
    formats = '{:<12} {:<}'

    # Print comm, key
    print(formats.format('COMM:', profile.comm.decode('utf-8')))
    print(formats.format('KEY:', profile.key))

    # Print status: frozen, normal, or training
    status = 'Normal' if profile.normal else 'Frozen' if profile.frozen else 'Training'
    print(formats.format('STATUS:', status))

    # Print normal time
    normal_time = datetime.datetime.fromtimestamp(profile.normal_time // 1000000000)
    normal_time = normal_time.strftime('%Y-%m-%d %H:%M:%S')
    print(formats.format('NORM TIME:', normal_time))

    # Print anomaly count
    print(formats.format('ANOMALIES:', profile.anomalies))

    # Print training, testing data
    print_profile_data(profile, 'train', show_empty)
    print_profile_data(profile, 'test', show_empty)

def __profile_key_type(s):
    """
    Wrapper for argparse.FileType that prepends config.profiles_dir to the provided string.

    To be used as an argparse type.
    """
    path = os.path.join(config.profiles_dir, s)
    return argparse.FileType(mode='rb')(path)

def parse_args(args=sys.argv[1:]):
    """
    Wrapper to parse arguments with argparse.
    """
    parser = argparse.ArgumentParser(description=DESCRIPTION, prog="ebph-inspect", epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    options = parser.add_mutually_exclusive_group(required=1)
    options.add_argument('-k', '--key', type=__profile_key_type, dest='profile',
            help=f"Inspect profile with key <KEY>.")
    options.add_argument('-p', '--path', type=argparse.FileType(mode='rb'), dest='profile',
            help=f"Inspect the profile located at <PATH>.")
    options.add_argument('-l', '--list', action='store_true',
            help=f"List all profiles in {config.profiles_dir}.")

    parser.add_argument('-e', '--empty', action='store_true',
            help='Show empty lookahead pairs instead of hiding.')

    args = parser.parse_args(args)

    # check for root
    if not (os.geteuid() == 0):
        parser.error("This script must be run with root privileges! Exiting.")

    return args

if __name__ == "__main__":
    args = parse_args()

    # List all profiles and exit
    if args.list:
        summary = []
        for fn in os.listdir(config.profiles_dir):
            with open(os.path.join(config.profiles_dir, fn), 'rb') as f:
                name = parse_profile(f).comm.decode('utf-8')
            summary.append((name, fn))
        for entry in sorted(summary, key=lambda item: (item[0].lower(), item[1])):
            print(f'{entry[0][:20]:<20} {entry[1]}')
        sys.exit(0)

    profile = parse_profile(args.profile)
    print_profile(profile, args.empty)
