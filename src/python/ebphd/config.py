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

    # How long ebpH should sleep between ticks in seconds?
    # Lower values imply higher CPU usage
    # Recommended value is around 1 second
    ticksleep = 0.1

    # When attempting to stop the daemon, how long do we wait before giving up?
    killtimeout = 20

    # Do not edit anything below this line ------------------------------------

    # ebpH data
    ebph_data_dir =  '/var/lib/ebpH'
    profiles_dir = os.path.join(ebph_data_dir, 'profiles')

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
        Config.setup_dir(Config.ebph_data_dir)
        Config.setup_dir(Config.profiles_dir)

        # configure logging
        logger = logging.getLogger('ebpH')
        logger.setLevel(Config.verbosity)

        handler = logging.handlers.WatchedFileHandler(Config.logfile)
        handler.setLevel(Config.verbosity)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        formatter.datefmt = '%Y-%m-%d %H:%M:%S'
        handler.setFormatter(formatter)

        logger.addHandler(handler)
