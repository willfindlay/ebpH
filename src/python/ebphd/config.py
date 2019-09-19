import os, sys, logging, logging.handlers

class Config():
    # Location where socket and pidfile should be stored
    socketdir = '/run'

    # Location where log files should be saved
    #logdir = '/var/log/ebph'
    logdir = '/tmp'

    # Verbosity level for logging
    # Possible values: logging.CRITICAL, logging.ERROR, logging.WARNING,
    #                  logging.INFO,     logging.DEBUG
    verbosity = logging.INFO

    # Do not edit anything below this line ------------------------------------

    # bpf filesystem config
    bpffs = '/sys/fs/bpf'
    ebphfs = os.path.join(bpffs, 'ebpH')
    profiles_path = os.path.join(ebphfs, 'profiles')

    # configure file locations
    socket = os.path.join(socketdir, 'ebph.sock')
    pidfile = os.path.join(socketdir, 'ebph.pid')
    logfile = os.path.join(logdir, 'ebph.log')

    @staticmethod
    def setup_dir(d):
        if not os.path.exists(d):
            os.makedirs(d)

    @staticmethod
    def init():
        # make sure directories are setup
        Config.setup_dir(Config.logdir)
        Config.setup_dir(Config.ebphfs)

        # configure logging
        logger = logging.getLogger('ebpH')
        logger.setLevel(Config.verbosity)

        handler = logging.handlers.WatchedFileHandler(Config.logfile)
        handler.setLevel(Config.verbosity)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        formatter.datefmt = '%Y-%m-%d %H:%M:%S'
        handler.setFormatter(formatter)

        logger.addHandler(handler)
