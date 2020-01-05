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
import socket
import signal
import time
import logging
import atexit
import threading
from collections import defaultdict

from daemon import Daemon
from bpf_program import BPFProgram
from server import EBPHUnixStreamServer, EBPHRequestDispatcher
import config
from utils import locks, to_json_bytes, from_json_bytes

# Register signal handlers
signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))

# The ebpH Daemon
class EBPHDaemon(Daemon):
    lock = threading.Lock()

    def __init__(self, args):
        # Init Daemon superclass
        super().__init__(config.pidfile, config.socket)

        # BPF Program
        should_save = not args.nosave
        should_load = not args.noload
        self.bpf_program = BPFProgram(should_save, should_load)

        # Set args
        self.args = args

        # Number of elapsed ticks
        self.tick_count = 0

        # Logging stuff
        self.logger = logging.getLogger('ebpH')

        # Request dispatcher for server
        self.request_dispatcher = EBPHRequestDispatcher(self)
        # TODO: register commands with dispatcher here
        self.request_dispatcher.register(self.start_monitoring)
        self.request_dispatcher.register(self.stop_monitoring)
        self.request_dispatcher.register(self.save_profiles)
        self.request_dispatcher.register(self.fetch_profile)
        self.request_dispatcher.register(self.fetch_all_profiles)
        self.request_dispatcher.register(self.fetch_process)
        self.request_dispatcher.register(self.fetch_all_processes)

    # Listen for incoming socket connections and dispatch to connection handler thread
    def listen_for_connections(self):
        self.logger.info("Starting ebpH server...")
        self.server = EBPHUnixStreamServer(self.request_dispatcher)
        self.logger.info(f"Server listening for connections on {self.server.server_address}")
        self.server.serve_forever()

    def tick(self):
        self.tick_count += 1

        if self.tick_count % config.saveinterval == 0:
            self.save_profiles()

        self.bpf_program.on_tick()

    def main(self):
        self.logger.info("Starting ebpH daemon...")
        self.bpf_program.load_bpf()

        # Spawn connection listener here
        self.connection_listener = threading.Thread(target=self.listen_for_connections)
        self.connection_listener.daemon = True
        self.connection_listener.start()

        # Event loop
        while True:
            self.tick()
            time.sleep(config.ticksleep)

    def stop(self):
        self.logger.info("Stopping ebpH daemon...")
        super().stop()

    # Commands below this line -----------------------------------
    # Return values must be json parsable

    @locks(lock)
    def start_monitoring(self):
        return self.bpf_program.start_monitoring()

    @locks(lock)
    def stop_monitoring(self):
        return self.bpf_program.stop_monitoring()

    @locks(lock)
    def save_profiles(self):
        return self.bpf_program.save_profiles()

    def fetch_profile(self, key):
        profile = self.bpf_program.fetch_profile(key)
        attrs = {'comm': profile.comm.decode('utf-8'),
                'key': profile.key,
                'frozen': profile.frozen,
                'normal': profile.normal,
                'normal_time': profile.normal_time,
                'normal_count': profile.normal_count,
                'last_mod_count': profile.last_mod_count,
                'train_count': profile.train_count,
                'anomalies': profile.anomalies,
                }
        return attrs

    def fetch_process(self, key):
        process = self.bpf_program.fetch_process(key)
        attrs = {'comm': profile.comm.decode('utf-8'),
                'key': profile.key,
                'frozen': profile.frozen,
                'normal': profile.normal,
                'normal_time': profile.normal_time,
                'normal_count': profile.normal_count,
                'last_mod_count': profile.last_mod_count,
                'train_count': profile.train_count,
                'anomalies': profile.anomalies,
                }
        return attrs

    def fetch_all_profiles(self):
        profiles = {}
        return profiles

    def fetch_all_processes(self):
        processes = {}
        return processes

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
        parser.add_argument('-v', dest='verbose', action='store_true',
                help=f"Set verbosity level to debug regardless of what is set in configuration options.")

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
