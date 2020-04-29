import os, sys
import atexit
import socket
import signal
import time
import threading
import logging
import logging.handlers
import struct

from flask import Flask
from flask.logging import default_handler
#from flask_restful import Resource

from ebpH.daemon_mixin import DaemonMixin
from ebpH.bpf_program import BPFProgram
from ebpH.utils import locks, to_json_bytes, from_json_bytes
from ebpH import defs

logger = logging.getLogger('ebph')

server = Flask(__name__)
wzlog = logging.getLogger('werkzeug')
wzlog.disabled = True
server.logger.disabled = True

class EBPHDaemon(DaemonMixin):
    """
    EBPHDaemon

    This class provides the logic for the daemon and exposes methods for interacting with the
    underlying BPFProgram class.

    Right now, the relationship bewteen the Daemon and BPFProgram is "has-a", but in the
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

        # Spawn connection listener here
        work_loop = threading.Thread(target=self.bpf_work_loop)
        work_loop.daemon = True
        work_loop.start()

        logger.info("Starting ebpH server...")
        server.run(debug=True)

    def stop_daemon(self):
        """
        Stop the daemon. Overloaded from base daemon class to print log info.
        """
        logger.info("Stopping ebpH daemon...")
        super().stop_daemon()

