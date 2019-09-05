#! /usr/bin/env python3

import os, sys, socket, atexit, time, argparse, logging
from threading import Thread
from signal import SIGTERM

from bcc import BPF, lib

# TODO: check bcc version here
#       maybe we could also somehow integrate bcc into the pipfile

from config import Config

OPERATIONS = ["start", "stop", "restart"]

def parse_args(args=[]):
    parser = argparse.ArgumentParser(description="Daemon script for ebpH.", prog="ebpH", epilog="To change any of the defaults above, edit config.py",
            formatter_class=argparse.RawTextHelpFormatter)

    #parser.add_argument('-s', dest='kernel_src', metavar="path/to/kernel/source/",
    #        help=f"Path to Linux Kernel source. Config.py will try some sensible defaults if this is not set.")

    parser.add_argument('operation', metavar="Operation", type=lambda s: str(s).lower(), choices=OPERATIONS,
            help=f"Operation you want to perform. Choices are {', '.join(OPERATIONS)}")

    args = parser.parse_args(args)
    return args

class Ebphd:
    def __init__(self, stdin="/dev/null",  stdout="/dev/null",  stderr="/dev/null"):
        self.pidfile = Config.daemon_pid_file
        self.socket_adr = Config.daemon_socket_adr

        self.stdin  = stdin
        self.stdout = stdout
        self.stderr = stderr

        # configure logging
        self.logger = logging.getLogger("ebph")

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

        print("Starting ebpH daemon...")
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
            self._del_pidfile()
            os.kill(pid, SIGTERM)
            print("Killed ebpH daemon successfully!")
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
            time.sleep(1)

if __name__ == "__main__":
    args = parse_args(sys.argv[1:])

    # check for root
    if not (os.geteuid() == 0):
        print("This script must be run with root privileges! Exiting.")
        sys.exit(-1)

    Config.init()

    ebphd = Ebphd()

    if args.operation == "start":
        ebphd.start()
    elif args.operation == "stop":
        ebphd.stop()
    elif args.operation == "restart":
        ebphd.restart()
