import os, sys, logging

class Config():
    # Location where socket and pidfile should be stored
    socketdir = '/run'

    # Location where log files should be saved
    logdir = '/var/log/ebph'

    # Verbosity level for logging
    # Possible values: logging.CRITICAL, logging.ERROR, logging.WARNING,
    #                  logging.INFO,     logging.DEBUG
    verbosity = logging.ERROR

    # Do not edit anything below this line ------------------------------------

    @staticmethod
    def init():
        if not os.path.exists(Config.logdir):
            os.makedirs(Config.logdir)

        # configure file locations
        Config.daemon_socket_adr = os.path.join(Config.socketdir, 'ebph.sock')
        Config.daemon_pid_file = os.path.join(Config.socketdir, 'ebph.pid')
        Config.logfile = os.path.join(Config.logdir, 'ebph.log')

        # configure logging
        logging.basicConfig(filename=Config.logfile, filemode='a',
                format='%(asctime)s - %(levelname)s: %(message)s',
                level=Config.verbosity,
                datefmt='%Y-%m-%d %H:%M:%S')
