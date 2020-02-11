#! /usr/bin/env python3

import os, sys
import argparse

from structs import EBPHProfile

import config
config.init()

DESCRIPTION = """
Inspect individual ebpH profiles saved on disk.
"""
# The ebpH daemon (ebphd) must be running in order to run this software.
# """

EPILOG = """
Example usage:
    sudo ebph-inspect -k 21342                   # Inspect profile with key 21342
    sudo ebph-inspect -p /tmp/testprofiles/21342 # Inspect profile stored in /tmp/testprofiles/21342
"""

def parse_profile(profile):
    print(profile.read())

def __profile_key_type(s):
    path = os.path.join(config.profiles_dir, s)
    return argparse.FileType(mode='rb')(path)

def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=DESCRIPTION, prog="ebph-inspect", epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    options = parser.add_mutually_exclusive_group()
    options.add_argument('-k', '--key', type=__profile_key_type, dest='profile',
            help=f"Inspect profile with key <KEY>.")
    options.add_argument('-p', '--path', type=argparse.FileType(mode='rb'), dest='profile',
            help=f"Inspect the profile located at <PATH>.")

    args = parser.parse_args(args)

    # check for root
    if not (os.geteuid() == 0):
        parser.error("This script must be run with root privileges! Exiting.")

    return args

if __name__ == "__main__":
    args = parse_args()
    parse_profile(args.profile)
