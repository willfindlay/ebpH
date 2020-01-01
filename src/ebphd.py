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
import config
import utils

# register handlers
signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))

# Decorator for ebpH commands
def command(func):
    def inner(*args, connection=None, **kwargs):
        # We need to send a reply if we are acting on behalf of a connection
        if connection:
            try:
                res = func(*args, **kwargs)
            except Exception as e:
                res = b'error'
                logger = logging.getLogger('ebpH')
                logger.error(f"Unable to complete request: {e}")
            if res is None:
                res = b'OK'
            connection.send(res)
        else:
            func(*args, **kwargs)
    return inner

# Manages a connection
class Connection():
    def __init__(self, sock, addr, handler):
        self.sock = sock
        self.addr = addr
        self.handler = handler

    # Start new thread to handle connection
    def start(self):
        self.thread = threading.Thread(target=self.handler, args=(self,))
        self.thread.start()

    # Close connection and join thread
    def stop(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.thread.join()

    def send(self, string):
        return self.sock.send(string)

    def recv(self):
        return self.sock.recv(config.socket_buff_size)

# The ebpH Daemon
class EBPHDaemon(Daemon):
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

        # Threading stuff
        self.command_lock = threading.Lock()
        self.connections = []
        self.close_connections = False

        self.commands = {
                b'stop_monitoring': self.stop_monitoring
                }

        self.register_exit_hooks()

    # Handle socket connections
    def handle_connection(self, connection):
        self.logger.debug(f"Opened connection with {connection.addr}")
        while True:
            try:
                data = connection.recv()
            except socket.error as e:
                self.logger.error(f"Error occurred in socket: {e}... Closing connection...")
                break

            # Exit conditions
            if not data:
                break

            # Do something with data
            self.commands[data](connection=connection)

        connection.sock.close()
        self.logger.debug(f"Closed connection with {connection.addr}")

    # Listen for incoming socket connections and dispatch to connection handler thread
    def listen_for_connections(self):
        while True:
            c, addr = self._socket.accept()

            # Start new connection_handler thread
            connection = Connection(c, addr, self.handle_connection)
            self.connections.append(connection)
            connection.start()

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

    def cleanup(self):
        self.logger.info('Closing active connections...')
        self.close_connections = True
        for connection in self.connections:
            connection.stop()
        self.logger.info('All active connections closed')

    def register_exit_hooks(self):
        atexit.unregister(self.cleanup)
        atexit.register(self.cleanup)
        self.logger.info("Registered daemon exit hooks")

    # Commands below this line -----------------------------------

    @command
    def start_monitoring(self):
        self.bpf_program.start_monitoring()

    @command
    def stop_monitoring(self):
        self.bpf_program.stop_monitoring()

    @command
    def save_profiles(self):
        self.bpf_program.save_profiles()

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
        e._bind_socket()
        e.main()
