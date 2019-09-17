#! /usr/bin/env python3

import os, sys, argparse, logging
from signal import SIGTERM

# TODO: check bcc version here
#       maybe we could also somehow integrate bcc into the pipfile

from config import Config
import utils

def cleanup(ebph):
    ebph.cleanup()

from ebph import ebpHD

OPERATIONS = ["start", "stop", "restart", "test"]

def parse_args(args=[]):
    parser = argparse.ArgumentParser(description="Daemon script for ebpH.", prog="ebpH", epilog="To change any of the defaults above, edit config.py",
            formatter_class=argparse.RawTextHelpFormatter)

    #parser.add_argument('-s', dest='kernel_src', metavar="path/to/kernel/source/",
    #        help=f"Path to Linux Kernel source. Config.py will try some sensible defaults if this is not set.")

    parser.add_argument('operation', metavar="Operation", type=lambda s: str(s).lower(), choices=OPERATIONS,
            help=f"Operation you want to perform. Choices are {', '.join(OPERATIONS)}")

    args = parser.parse_args(args)
    return args

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])

    # check for root
    if not (os.geteuid() == 0):
        print("This script must be run with root privileges! Exiting.")
        sys.exit(-1)

    Config.init()

    e = ebpHD()

    if args.operation == "start":
        e.start()
    elif args.operation == "stop":
        e.stop()
    elif args.operation == "restart":
        e.restart()
    elif args.operation == "test":
        e.main()
