#! /usr/bin/env python3

import os, sys, argparse, logging, logging.handlers
from signal import SIGTERM

# TODO: check bcc version here
#       maybe we could also somehow integrate bcc into the pipfile

from config import Config
import utils

from ebph import ebpHD

OPERATIONS = ["start", "stop", "restart"]

def parse_args(args=[]):
    parser = argparse.ArgumentParser(description="Daemon script for ebpH.", prog="ebpH", epilog="To change any of the defaults above, edit config.py",
            formatter_class=argparse.RawTextHelpFormatter)

    #parser.add_argument('-s', dest='kernel_src', metavar="path/to/kernel/source/",
    #        help=f"Path to Linux Kernel source. Config.py will try some sensible defaults if this is not set.")

    parser.add_argument('operation', metavar="Operation", type=lambda s: str(s).lower(), choices=OPERATIONS, nargs='?',
            help=f"Operation you want to perform. Not allowed with --nodaemon. Choices are: {', '.join(OPERATIONS)}.")
    parser.add_argument('--nodaemon', dest='nodaemon', action='store_true',
            help=f"Run this as a foreground process instead of a daemon.")
    parser.add_argument('--nolog', dest='nolog', action='store_true',
            help=f"Write to stderr instead of logfile. In daemon mode, this will simply not write any logging information.")
    parser.add_argument('-v', dest='verbose', action='store_true',
            help=f"Set verbosity level to debug regardless of what is set in configuration options.")

    args = parser.parse_args(args)

    # error checking
    if args.nodaemon and args.operation:
        parser.error("You cannot specify an operation with the --nodaemon flag.")
    if not (args.nodaemon or args.operation):
        parser.error("You must either specify an operation or set the --nodaemon flag.")

    return args

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])

    # check for root
    if not (os.geteuid() == 0):
        print("This script must be run with root privileges! Exiting.")
        sys.exit(-1)

    # check verbosity flag
    if args.verbose:
        Config.verbosity = logging.DEBUG

    Config.init()

    if args.nolog:
        logger = logging.getLogger('ebpH')

        # create and configure a handler for stderr
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(Config.verbosity)
        logger.addHandler(stream_handler)

        # set formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        formatter.datefmt = '%Y-%m-%d %H:%M:%S'
        stream_handler.setFormatter(formatter)

        # disable file handlers
        logger.handlers = [h for h in logger.handlers if not isinstance(h, logging.handlers.WatchedFileHandler)]

    e = ebpHD()

    if args.operation == "start":
        e.start()
    elif args.operation == "stop":
        e.stop()
    elif args.operation == "restart":
        e.restart()
    elif args.nodaemon:
        e._bind_socket()
        e.main()
