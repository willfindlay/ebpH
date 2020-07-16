"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    Copyright (C) 2019-2020  William Findlay

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

    Daemon logic using python-daemon.

    2020-Jul-13  William Findlay  Created this.
"""

import time
import os, sys
import signal

from daemon import DaemonContext, pidfile

from ebph import defs
from ebph.logger import get_logger

logger = get_logger()

class DaemonMixin:
    def loop_forever(self):
        raise NotImplementedError('Implement loop_forever(self) in the subclass.')

    def get_pid(self):
        """
        Get pid of the running daemon.
        """
        try:
            with open(defs.PIDFILE, 'r') as f:
               return int(f.read().strip())
        except:
            return None

    def stop_daemon(self):
        """
        Stop the daemon.
        """
        print('Stopping ebpH daemon...')
        pid = self.get_pid()
        try:
            os.kill(pid, signal.SIGTERM)
        except TypeError:
            logger.warn(f'Attempted to kill daemon with pid {pid}, but no such process exists')
            print(f'Attempted to kill daemon with pid {pid}, but no such process exists')

    def start_daemon(self):
        """
        Start the daemon.
        """
        if self.get_pid():
            logger.error(f'ebpH daemon is already running! If you believe this is an error, try deleting {defs.PIDFILE}.')
            print(f'ebpH daemon is already running! If you believe this is an error, try deleting {defs.PIDFILE}.')
            sys.exit(-1)
        print('Starting ebpH daemon...')
        logger.info('Starting ebpH daemon...')
        with DaemonContext(
                umask=0o022,
                working_directory=defs.EBPH_DATA_DIR,
                pidfile=pidfile.TimeoutPIDLockFile(defs.PIDFILE),
                # Necessary to preserve logging
                files_preserve=[handler.stream for handler in logger.handlers]
                ):
            logger.info('ebpH daemon started successfully!')
            self.loop_forever()

    def restart_daemon(self):
        """
        Restart the daemon.
        """
        self.stop_daemon()
        time.sleep(1)
        self.start_daemon()
