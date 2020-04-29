import os, sys
import atexit
import socket
import signal
import time
import threading
import logging
import logging.handlers
import struct
import argparse

from ebpH.daemon_mixin import DaemonMixin
from ebpH.bpf_program import BPFProgram
from ebpH.utils import locks, to_json_bytes, from_json_bytes
from ebpH import defs
from ebpH.logger import setup_logger, get_logger

logger = get_logger()

class EBPHDaemon(DaemonMixin):
    """
    EBPHDaemon

    This class provides the logic for the daemon and exposes methods for interacting with the
    underlying BPFProgram class.

    Right now, the relationship bewteen the Daemon and BPFProgram is composition, but in the
    future this might become inheritance. Not sure what the best approach is here.
    """
    def __init__(self, args):
        # BPF Program
        self.bpf_program = BPFProgram(args)

        # Set args
        self.args = args

        # Number of elapsed ticks
        self.tick_count = 0

        # Request dispatcher for server
        #self.request_dispatcher = EBPHRequestDispatcher(self)
        # Register commands with dispatcher
        #self.request_dispatcher.register(self.bpf_program.start_monitoring)
        #self.request_dispatcher.register(self.bpf_program.stop_monitoring)
        #self.request_dispatcher.register(self.bpf_program.is_monitoring)
        #self.request_dispatcher.register(self.bpf_program.status)
        #self.request_dispatcher.register(self.bpf_program.save_profiles)
        #self.request_dispatcher.register(self.bpf_program.fetch_profile)
        #self.request_dispatcher.register(self.bpf_program.fetch_profiles)
        #self.request_dispatcher.register(self.bpf_program.fetch_process)
        #self.request_dispatcher.register(self.bpf_program.fetch_processes)
        #self.request_dispatcher.register(self.bpf_program.normalize)
        #self.request_dispatcher.register(self.bpf_program.set_logging_new_sequences)
        # TODO: the following:
        #self.request_dispatcher.register(self.reset_profile)
        #self.request_dispatcher.register(self.inspect_profile)

    def tick(self):
        """
        Invoked on every tick in the main event loop.
        """
        self.tick_count += 1

        if self.tick_count % defs.saveinterval == 0:
            self.bpf_program.save_profiles()

        self.bpf_program.on_tick()

    def bpf_work_loop(self):
        while True:
            self.tick()
            time.sleep(defs.ticksleep)

    def loop_forever(self):
        """
        Main daemon setup + event loop.
        """
        logger.info("Starting ebpH daemon...")
        self.bpf_program.load_bpf()

        work_loop = threading.Thread(target=self.bpf_work_loop)
        work_loop.daemon = True
        work_loop.start()

        from ebpH.api import app
        logger.info("Starting ebpH server...")
        app.run(debug=True, port=1000)

    def stop_daemon(self):
        """
        Stop the daemon. Overloaded from base daemon class to print log info.
        """
        logger.info("Stopping ebpH daemon...")
        super().stop_daemon()

def main():
    OPERATIONS = ["start", "stop", "restart"]

    def parse_args(args=[]):
        parser = argparse.ArgumentParser(description="Daemon script for ebpH.",
                prog="ebphd", epilog="Condiguration file can be found at /etc/ebpH/ebpH.cfg",
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
    defs.init()
    setup_logger(args)

    global ebphd
    ebphd = EBPHDaemon(args)

    if args.operation == "start":
        ebphd.start_daemon()
    elif args.operation == "stop":
        ebphd.stop_daemon()
    elif args.operation == "restart":
        ebphd.restart_daemon()
    elif args.nodaemon:
        ebphd.loop_forever()
