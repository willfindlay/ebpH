"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    ebpH Copyright (C) 2019-2020  William Findlay
    pH   Copyright (C) 1999-2003 Anil Somayaji and (C) 2008 Mario Van Velzen

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Main ebpH daemon.

    2020-Jul-13  William Findlay  Created this.
"""

import sys
import time
import argparse
import os
import signal
import threading
from typing import NoReturn, List


from ebph.logger import get_logger
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
    def __init__(self, args: argparse.Namespace) -> 'EBPHDaemon':
        # BPF Program
        self.bpf_program = None

        self.debug = args.debug
        self.log_sequences = args.log_sequences
        self.auto_save = not args.nosave
        self.auto_load = not args.noload

    def tick(self) -> None:
        """
        Invoked on every tick in the main event loop.
        """
        self.bpf_program.on_tick()

    def loop_forever(self) -> NoReturn:
        """
        Main daemon setup + event loop.
        """
        self.bind_socket()

        self._init_bpf_program()

        bpf_thread = threading.Thread(target=self._bpf_work_loop)
        bpf_thread.daemon = True
        bpf_thread.start()

        from ebph.api import API
        logger.info('Starting ebpH server...')
        API.connect_bpf_program(self.bpf_program)
        API.serve_forever()

    def stop_daemon(self, in_restart: bool = False) -> None:
        """
        Stop the daemon. Overloaded from base daemon class to print log info.
        """
        logger.info("Stopping ebpH daemon...")
        super().stop_daemon(in_restart=in_restart)

    def _init_bpf_program(self) -> None:
        assert self.bpf_program is None
        from ebph.bpf_program import BPFProgram
        self.bpf_program = BPFProgram(debug=self.debug,
                log_sequences=self.log_sequences, auto_save=self.auto_save,
                auto_load=self.auto_load)
        global bpf_program
        bpf_program = self.bpf_program

    def _bpf_work_loop(self) -> NoReturn:
        while 1:
            self.tick()
            time.sleep(defs.TICK_SLEEP)


OPERATIONS = ["start", "stop", "restart"]


def parse_args(args: List[str] = []) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Daemon script for ebpH.",
            prog="ebphd", #epilog="Configuration file can be found at /etc/ebpH/ebpH.cfg",
            formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('operation', metavar="Operation", type=lambda s: str(s).lower(),
            choices=OPERATIONS, nargs='?',
            help=f"Operation you want to perform. Not allowed with --nodaemon. "
            f"Choices are: {', '.join(OPERATIONS)}.")
    parser.add_argument('--nodaemon', dest='nodaemon', action='store_true',
            help=f"Run this as a foreground process instead of a daemon.")
    parser.add_argument('--noserver', dest='noserver', action='store_true',
            help=f"Run ebphd without starting the server.")
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
    # Quick testing mode. This option sets --nodaemon --nolog --nosave --noload flags.
    parser.add_argument('--testing', action='store_true',
            help=argparse.SUPPRESS)

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


def main(sys_args: List[str] = sys.argv[1:]) -> NoReturn:
    args = parse_args(sys_args)
    defs.init(args)

    global logger
    logger = get_logger()

    ebphd = EBPHDaemon(args)

    if args.operation == "start":
        try:
            ebphd.start_daemon()
        except Exception as e:
            logger.error('Unable to start daemon', exc_info=e)
            sys.exit(-1)
    elif args.operation == "stop":
        try:
            ebphd.stop_daemon()
        except Exception as e:
            logger.error('Unable to stop daemon', exc_info=e)
            sys.exit(-1)
    elif args.operation == "restart":
        try:
            ebphd.restart_daemon()
        except Exception as e:
            logger.error('Unable to restart daemon', exc_info=e)
            sys.exit(-1)
    elif args.nodaemon:
        ebphd.loop_forever()
