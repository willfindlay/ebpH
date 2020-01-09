# ebpH --  An eBPF intrusion detection program.
# -------  Monitors system call patterns and detect anomalies.
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
import atexit
import socket
import signal
import time

import config

class Daemon:
    def __init__(self, pidfile, socket, stdin="/dev/null",  stdout="/dev/null",  stderr="/dev/null"):
        self.pidfile = pidfile
        self.socket_adr = socket

        self.stdin  = stdin
        self.stdout = stdout
        self.stderr = stderr

    def _daemonize(self):
        # first fork
        try:
            pid = os.fork()
            if pid != 0:
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Failed first fork while daemonizing: {e.errno} {e.strerror}\n")
            sys.exit(-1)

        # only root should be able to read/write to ebph files
        # and traverse ebph directories
        os.umask(0o033)

        os.chdir("/")
        os.setsid()

        # second fork
        try:
            pid = os.fork()
            if pid != 0:
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Failed second fork while daemonizing: {e.errno} {e.strerror}\n")
            sys.exit(-1)

        # create stdin, stdout, stderr files if they don't exist
        stdin_path  = os.path.dirname(self.stdin)
        stdout_path = os.path.dirname(self.stdout)
        stderr_path = os.path.dirname(self.stderr)
        if not stdin_path:
            os.makedirs(stdin_path)
        if not stdout_path:
            os.makedirs(stdout_path)
        if not stderr_path:
            os.makedirs(stderr_path)

        # redirect standard fds
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(self.stdin, 'r')
        so = open(self.stdout, 'a+')
        se = open(self.stderr, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self._del_pidfile)
        pid = str(os.getpid())
        with open(self.pidfile, 'w') as f:
            f.write(f"{pid}\n")

    def _del_pidfile(self):
        os.unlink(self.pidfile)

    def start(self):
        # check for a pidfile
        try:
            with open(self.pidfile, 'r') as f:
                pid = int(f.read().strip())
        except IOError:
            pid = None

        if pid:
            sys.stderr.write(f"ebpH daemon is already running. If you believe you are seeing this by mistake, delete {config.pidfile}.\n")
            sys.exit(-1)

        print("Starting ebpH daemon...")
        self._daemonize()
        self.main()

    def stop(self):
        # check for a pidfile
        try:
            with open(self.pidfile, 'r') as f:
                pid = int(f.read().strip())
        except IOError:
            pid = None

        if not pid:
            sys.stderr.write(f"ebpH daemon is not currently running. If you believe you are seeing this by mistake, try killing the process manually.\n")
            return

        # kill the process
        try:
            print("Attempting to kill ebpH daemon...")
            os.kill(pid, signal.SIGTERM)
            timeout = 0
            while os.path.exists(self.pidfile):
                timeout = timeout + 1
                time.sleep(1)
                if timeout >= config.killtimeout:
                    sys.stderr.write(f"Timeout reached. You may want to delete {self.pidfile} and kill the daemon manually.\n")
                    sys.exit(-1)
            print("Killed ebpH daemon successfully!")
        except OSError as e:
            if e.strerror.find("No such process") >= 0:
                if os.path.exists(self.pidfile):
                    self._del_pidfile()
            sys.stderr.write(f"Failed to kill ebpH daemon: {e.errno} {e.strerror}\n")
            sys.exit(-1)

    def restart(self):
        self.stop()
        self.start()

    # overload this
    def main(self):
        while True:
            time.sleep(1)

