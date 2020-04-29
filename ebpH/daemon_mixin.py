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
import signal

from daemon import DaemonContext, pidfile

from ebpH import defs
from ebpH.logger import get_logger, LoggerWriter

logger = get_logger()

class DaemonMixin:
    def loop_forever(self):
        raise NotImplementedError('Implement loop_forever(self) in the subclass.')

    def get_pid(self):
        """
        Get pid of the running daemon.
        """
        try:
            with open(defs.pidfile, 'r') as f:
               return int(f.read().strip())
        except:
            return None

    def stop_daemon(self):
        """
        Stop the daemon.
        """
        pid = self.get_pid()
        try:
            os.kill(pid, signal.SIGTERM)
        except TypeError:
            logger.warn(f'Attempted to kill daemon with pid {pid}, but no such process exists')

    def start_daemon(self):
        """
        Start the daemon.
        """
        with DaemonContext(
                umask=0o022,
                working_directory=defs.ebph_data_dir,
                pidfile=pidfile.TimeoutPIDLockFile(defs.pidfile),
                # Necessary to preserve logging
                files_preserve=[handler.stream for handler in logger.handlers]
                ):
            # Redirect stdout and stderr to logger
            sys.stdout = LoggerWriter(logger.debug)
            sys.stderr = LoggerWriter(logger.error)
            self.loop_forever()

    def restart_daemon(self):
        """
        Restart the daemon.
        """
        self.stop_daemon()
        self.start_daemon()
