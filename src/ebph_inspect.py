#! /usr/bin/env python3

import os, sys
import argparse

import bcc.syscall

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

def syscall_name(num: int):
    """
    Convert a system call number into a name.

    Args:
        num: system call number

    Return:
        Uppercase string system call name
    """
    name_bin = bcc.syscall.syscall_name(num)
    return name_bin.decode('utf-8').upper()

def print_profile_data(profile: EBPHProfile, data: 'train' or 'test'):
    """
    Print training or testing profile data for an EBPHProfile

    Args:
        profile: EBPHProfile
        data: 'train' or 'test'
    """
    assert data == 'train' or data == 'test'
    profile_data = profile.train if data == 'train' else profile.test
    for prev, row in enumerate(profile_data.flags):
        for curr, flag in enumerate(row):
            if flag != 0:
                print(syscall_name(curr), syscall_name(prev), bin(flag)[2:].zfill(8))

def __profile_key_type(s):
    """
    Wrapper for argparse.FileType that prepends config.ebph_data_dir to the provided string.

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
    profile = parse_profile(args.profile)
    print_profile_data(profile, 'test')
