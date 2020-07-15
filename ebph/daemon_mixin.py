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
