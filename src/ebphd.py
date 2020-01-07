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
import logging
import logging.handlers
import pwd
import grp
import stat

from daemon import EBPHDaemon
import config
from utils import setup_dir

# Register signal handlers
signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))

if __name__ == "__main__":
    OPERATIONS = ["start", "stop", "restart"]

    def parse_args(args=[]):
        parser = argparse.ArgumentParser(description="Daemon script for ebpH.", prog="ebphd", epilog="Configuration file is located in config.py",
                formatter_class=argparse.RawTextHelpFormatter)

        parser.add_argument('operation', metavar="Operation", type=lambda s: str(s).lower(), choices=OPERATIONS, nargs='?',
                help=f"Operation you want to perform. Not allowed with --nodaemon. Choices are: {', '.join(OPERATIONS)}.")
        parser.add_argument('--nodaemon', dest='nodaemon', action='store_true',
                help=f"Run this as a foreground process instead of a daemon.")
        parser.add_argument('--nolog', dest='nolog', action='store_true',
                help=f"Write to stderr instead of logfile. In daemon mode, this will simply not write any logging information.")
        parser.add_argument('--nosave', dest='nosave', action='store_true',
                help=f"Don't save profiles on exit.")
        parser.add_argument('--noload', dest='noload', action='store_true',
                help=f"Don't load profiles.")
        parser.add_argument('--debug', action='store_true',
                help=f"Run in debug mode. Side effect: sets verbosity level to debug regardless of what is set in configuration options.")
        parser.add_argument('--ludikris', action='store_true',
                help=f"Run in LudiKRIS mode. This purposely sets insane options to help with testing.")

        args = parser.parse_args(args)

        # check for root
        if not (os.geteuid() == 0):
            parser.error("This script must be run with root privileges! Exiting.")

        # error checking
        if args.nodaemon and args.operation:
            parser.error("You cannot specify an operation with the --nodaemon flag.")
        if not (args.nodaemon or args.operation):
            parser.error("You must either specify an operation or set the --nodaemon flag.")

        return args

    args = parse_args(sys.argv[1:])
    config.init()

    uid = pwd.getpwnam("root").pw_uid
    gid = grp.getgrnam("root").gr_gid

    # Setup logdir
    setup_dir(config.logdir)

    # Setup logfile
    try:
        os.chown(config.logfile, uid, gid)
    except FileNotFoundError:
        pass

    # Setup data dir and make sure permissions are correct
    setup_dir(config.ebph_data_dir)
    os.chown(config.ebph_data_dir, uid, gid)
    os.chmod(config.ebph_data_dir, 0o700 | stat.S_ISVTX)

    # Setup profiles dir and make sure permissions are correct
    setup_dir(config.profiles_dir)
    os.chown(config.profiles_dir, uid, gid)
    os.chmod(config.profiles_dir, 0o700)

    # Configure logging
    if args.debug:
        config.verbosity = logging.DEBUG
    logger = logging.getLogger('ebpH')
    logger.setLevel(config.verbosity)

    handler = logging.handlers.WatchedFileHandler(config.logfile)
    handler.setLevel(config.verbosity)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
    formatter.datefmt = '%Y-%m-%d %H:%M:%S'
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    # Handle nolog argument
    if args.nolog:
        logger = logging.getLogger('ebpH')

        # create and configure a handler for stderr
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(config.verbosity)
        logger.addHandler(stream_handler)

        # set formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        formatter.datefmt = '%Y-%m-%d %H:%M:%S'
        stream_handler.setFormatter(formatter)

        # disable file handlers
        logger.handlers = [h for h in logger.handlers if not isinstance(h, logging.handlers.WatchedFileHandler)]

    e = EBPHDaemon(args)

    if args.operation == "start":
        e.start()
    elif args.operation == "stop":
        e.stop()
    elif args.operation == "restart":
        e.restart()
    elif args.nodaemon:
        e.main()
