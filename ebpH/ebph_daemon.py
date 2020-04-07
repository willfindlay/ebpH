import os, sys
import atexit
import socket
import signal
import time
import threading
import logging
import logging.handlers
import struct

from ebpH.daemon import Daemon
from ebpH.bpf_program import BPFProgram
from ebpH.server import EBPHUnixStreamServer, EBPHRequestDispatcher
from ebpH.utils import locks, to_json_bytes, from_json_bytes
from ebpH import defs

logger = logging.getLogger('ebph')

class EBPHDaemon(Daemon):
    """
    EBPHDaemon

    This class provides the logic for the daemon and exposes methods for interacting with the
    underlying BPFProgram class.

    Right now, the relationship bewteen the Daemon and BPFProgram is "has-a", but in the
    future this might become inheritance. Not sure what the best approach is here.
    """
    def __init__(self, args):
        # Init Daemon superclass
        super().__init__(defs.pidfile, defs.socket)

        # BPF Program
        self.bpf_program = BPFProgram(args)

        # Set args
        self.args = args

        # Number of elapsed ticks
        self.tick_count = 0

        # Request dispatcher for server
        self.request_dispatcher = EBPHRequestDispatcher(self)
        # Register commands with dispatcher
        self.request_dispatcher.register(self.bpf_program.start_monitoring)
        self.request_dispatcher.register(self.bpf_program.stop_monitoring)
        self.request_dispatcher.register(self.bpf_program.is_monitoring)
        self.request_dispatcher.register(self.bpf_program.status)
        self.request_dispatcher.register(self.bpf_program.save_profiles)
        self.request_dispatcher.register(self.bpf_program.fetch_profile)
        self.request_dispatcher.register(self.bpf_program.fetch_profiles)
        self.request_dispatcher.register(self.bpf_program.fetch_process)
        self.request_dispatcher.register(self.bpf_program.fetch_processes)
        self.request_dispatcher.register(self.bpf_program.normalize)
        self.request_dispatcher.register(self.bpf_program.set_logging_new_sequences)
        # TODO: the following:
        #self.request_dispatcher.register(self.reset_profile)
        #self.request_dispatcher.register(self.inspect_profile)

    # Listen for incoming socket connections and dispatch to connection handler thread
    def listen_for_connections(self):
        """
        Called by the connection handler thread to listen for incoming socket connections.
        """
        logger.info("Starting ebpH server...")
        self.server = EBPHUnixStreamServer(self.request_dispatcher)
        logger.info(f"Server listening for connections on {self.server.server_address}")
        self.server.serve_forever()

    def tick(self):
        """
        Invoked on every tick in the main event loop.
        """
        self.tick_count += 1

        if self.tick_count % defs.saveinterval == 0:
            self.bpf_program.save_profiles()

        self.bpf_program.on_tick()

    def main(self):
        """
        Main daemon setup + event loop.
        """
        logger.info("Starting ebpH daemon...")
        self.bpf_program.load_bpf()

        # Spawn connection listener here
        self.connection_listener = threading.Thread(target=self.listen_for_connections)
        self.connection_listener.daemon = True
        self.connection_listener.start()

        # Event loop
        while True:
            self.tick()
            time.sleep(defs.ticksleep)

    def stop(self):
        """
        Stop the daemon. Overloaded from base daemon class to print log info.
        """
        logger.info("Stopping ebpH daemon...")
        super().stop()

