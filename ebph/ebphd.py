import sys
import time
import argparse
import os
import signal
import threading

from ebph.logger import get_logger, setup_logger, LoggerWriter
from ebph.daemon_mixin import DaemonMixin
from ebph import defs

signal.signal(signal.SIGTERM, lambda _, __: sys.exit())
signal.signal(signal.SIGINT, lambda _, __: sys.exit())

class EBPHDaemon(DaemonMixin):
    """
    EBPHDaemon

    This class provides the logic for the daemon and exposes methods for interacting with the
    underlying BPFProgram class.
    """
    def __init__(self, args):
        # BPF Program
        self.bpf_program = None

        self.debug = args.debug
        self.log_sequences = args.log_sequences

        # Number of elapsed ticks
        self.tick_count = 0

    def tick(self):
        """
        Invoked on every tick in the main event loop.
        """
        self.tick_count += 1

        if self.tick_count % defs.PROFILE_SAVE_INTERVAL == 0:
            self.bpf_program.save_profiles()

        self.bpf_program.on_tick()

    def _init_bpf_program(self):
        assert self.bpf_program is None
        from ebph.bpf_program import BPFProgram
        self.bpf_program = BPFProgram(debug=self.debug, log_sequences=self.log_sequences)
        global bpf_program
        bpf_program = self.bpf_program

    def _bpf_work_loop(self):
        while 1:
            self.tick()
            time.sleep(defs.TICK_SLEEP)

    def loop_forever(self):
        """
        Main daemon setup + event loop.
        """
        self._init_bpf_program()

        server_thread = threading.Thread(target=self._bpf_work_loop)
        server_thread.daemon = True
        server_thread.start()

        from ebph.api import serve_forever
        logger.info('Starting ebpH server...')
        serve_forever()


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
                prog="ebphd", #epilog="Configuration file can be found at /etc/ebpH/ebpH.cfg",
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
        parser.add_argument('--logseq', dest='log_sequences', action='store_true',
                help=f"Log new sequences. WARNING: This option can use a lot of resources if profiles are not stable!")
        parser.add_argument('--nosave', dest='nosave', action='store_true',
                help=f"Don't save profiles on exit.")
        parser.add_argument('--noload', dest='noload', action='store_true',
                help=f"Don't load profiles.")
        parser.add_argument('--debug', action='store_true',
                help=f"Run in debug mode. Side effect: sets verbosity level to debug regardless of what is set in configuration options.")
        parser.add_argument('--testing', action='store_true',
                help=f"Quick testing mode. This option sets --nodaemon --nolog --nosave --noload flags.")

        args = parser.parse_args(args)

        # Quick and dirty testing mode
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
    # TODO: intialize folders here
    setup_logger(args)

    global logger
    logger = get_logger()

    ebphd = EBPHDaemon(args)

    #logger.debug(f"ebphd.py path: {path(__file__)}")

    if args.operation == "start":
        ebphd.start_daemon()
    elif args.operation == "stop":
        ebphd.stop_daemon()
    elif args.operation == "restart":
        ebphd.restart_daemon()
    elif args.nodaemon:
        ebphd.loop_forever()
