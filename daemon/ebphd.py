#! /usr/bin/env python3

import os, sys, socket, atexit, time, argparse
from threading import Thread
from signal import SIGTERM

from bcc import BPF, lib

# TODO: check bcc version here
#       maybe we could also somehow integrate bcc into the pipfile

from config import Config

class Ebphd:
    def __init__(self):
        self.pidfile = Config.daemon_pid_file
        self.socket_adr = Config.daemon_socket_adr

        self.stdin = "/dev/null"
        self.stdout = "/dev/null"
        self.stderr = "/dev/null"

    def _bind_socket(self):
        # make sure socket doesn't already exist
        try:
            os.unlink(self.socket_adr)
        except OSError:
            if os.path.exists(self.socket_adr):
                raise

        # init socket
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # set appropriate permissions for socket
        old_umask = os.umask(0o177)
        # bind socket
        self._socket.bind(self.socket_adr)

        # restore old umask
        os.umask(old_umask)

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
        stdin_path = os.path.dirname(self.stdin)
        stdout_path = os.path.dirname(self.stdout)
        stderr_path = os.path.dirname(self.stderr)
        if not stdin_path:
            os.path.makedirs(stdin_path)
        if not stdout_path:
            os.path.makedirs(stdout_path)
        if not stderr_path:
            os.path.makedirs(stderr_path)

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
            sys.stderr.write(f"ebpH daemon is already running. If you believe you are seeing this by mistake, delete /run/ebphd.pid.\n")
            sys.exit(-1)

        self._daemonize()
        self._bind_socket()
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
            os.kill(pid, SIGTERM)
            time.sleep(0.1)
        except OSError as e:
            if e.strerror.find("No such process") >= 0:
                if os.path.exists(self.pidfile):
                    os.unlink(self.pidfile)
            sys.stderr.write(f"Failed to kill ebpH daemon: {e.errno} {e.strerror}\n")
            sys.exit(-1)

    def restart(self):
        self.stop()
        self.start()

    def main(self):
        while True:
            print("listening...")
            time.sleep(1)

if __name__ == "__main__":
    # check for root
    if not (os.geteuid() == 0):
        print("This script must be run with root privileges! Exiting.")
        sys.exit(-1)

    ebphd = Ebphd()
    ebphd.start()
