#! /usr/bin/env python3

# ebpH  An eBPF intrusion detection program. Monitors system call patterns and detect anomalies.
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
# Anil Somayaji (soma@scs.carleton.ca)
#
# Based on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# USAGE: ebphd <COMMAND>
#
# Licensed under GPL v2 License

import os, sys
import argparse
import signal
from logger import setup_logger
import pwd
import grp
import stat

from ebph_daemon import EBPHDaemon
from utils import setup_dir
import config
config.init()

if __name__ == "__main__":
    OPERATIONS = ["start", "stop", "restart"]

    def parse_args(args=[]):
        parser = argparse.ArgumentParser(description="Daemon script for ebpH.",
                prog="ebphd", epilog="Configuration file is located in config.py",
                formatter_class=argparse.RawDescriptionHelpFormatter)

        parser.add_argument('operation', metavar="Operation", type=lambda s: str(s).lower(),
                choices=OPERATIONS, nargs='?',
                help=f"Operation you want to perform. Not allowed with --nodaemon. "
                "Choices are: {', '.join(OPERATIONS)}.")
        parser.add_argument('--nodaemon', dest='nodaemon', action='store_true',
                help=f"Run this as a foreground process instead of a daemon.")
        parser.add_argument('--nolog', dest='nolog', action='store_true',
                help=f"Write to stderr instead of logfile. In daemon mode, "
                "this will simply not write any logging information.")
        parser.add_argument('--nosave', dest='nosave', action='store_true',
                help=f"Don't save profiles on exit.")
        parser.add_argument('--noload', dest='noload', action='store_true',
                help=f"Don't load profiles.")
        parser.add_argument('--debug', action='store_true',
                help=f"Run in debug mode. Side effect: sets verbosity level to debug regardless of what is set in configuration options.")
        parser.add_argument('--ludikris', action='store_true',
                help=f"Run in LudiKRIS mode. This purposely sets insane options to help with testing.")
        parser.add_argument('--testing', action='store_true',
                help=f"Quick testing mode. This option sets --nodaemon --nolog --nosave --noload flags.")

        args = parser.parse_args(args)

        # Quick and Dirty Mode
        if args.testing:
            args.nodaemon = True
            args.nolog = True
            args.nosave = True
            args.noload = True

        # Check for root
        if not (os.geteuid() == 0):
            parser.error("This script must be run with root privileges! Exiting.")

        # Error checking
        if args.nodaemon and args.operation:
            parser.error("You cannot specify an operation with the --nodaemon flag.")
        if not (args.nodaemon or args.operation):
            parser.error("You must either specify an operation or set the --nodaemon flag.")

        return args

    args = parse_args(sys.argv[1:])
    setup_logger(args)

    e = EBPHDaemon(args)

    if args.operation == "start":
        e.start()
    elif args.operation == "stop":
        e.stop()
    elif args.operation == "restart":
        e.restart()
    elif args.nodaemon:
        e.main()
