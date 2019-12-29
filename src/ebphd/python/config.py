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

import os, sys, pwd, grp, stat, logging, logging.handlers

class Config():
    # Location where socket and pidfile should be stored
    socketdir = '/run'

    # Location where log files should be saved
    logdir = '/var/log/ebpH'

    # Verbosity level for logging
    # Possible values: logging.CRITICAL, logging.ERROR, logging.WARNING,
    #                  logging.INFO,     logging.DEBUG
    verbosity = logging.INFO

    # How long ebpH should sleep between ticks in seconds?
    # Lower values imply higher CPU usage
    # Recommended value is around 1 second
    ticksleep = 0.1

    # How many ticks between automatic saves
    saveinterval = 6000 # about 10 minutes

    # When attempting to stop the daemon, how long do we wait before giving up?
    killtimeout = 20

    # ebpH data directory
    # WARNING: Don't pick a directory you're already using
    #          The permissions will be changed
    ebph_data_dir =  '/var/lib/ebpH'

    # Do not edit anything below this line ------------------------------------

    @staticmethod
    def setup_dir(d):
        if not os.path.exists(d):
            os.makedirs(d)

    @staticmethod
    def init():
        # Read defaults
        Config.profiles_dir = os.path.join(Config.ebph_data_dir, 'profiles')

        # configure file locations
        Config.socket = os.path.join(Config.socketdir, 'ebph.sock')
        Config.pidfile = os.path.join(Config.socketdir, 'ebph.pid')
        Config.logfile = os.path.join(Config.logdir, 'ebph.log')

        uid = pwd.getpwnam("root").pw_uid
        gid = grp.getgrnam("root").gr_gid

        # Setup logdir
        Config.setup_dir(Config.logdir)

        # Setup logfile
        try:
            os.chown(Config.logfile, uid, gid)
        except FileNotFoundError:
            pass

        # Setup data dir and make sure permissions are correct
        Config.setup_dir(Config.ebph_data_dir)
        os.chown(Config.ebph_data_dir, uid, gid)
        os.chmod(Config.ebph_data_dir, 0o700 | stat.S_ISVTX)

        # Setup profiles dir and make sure permissions are correct
        Config.setup_dir(Config.profiles_dir)
        os.chown(Config.profiles_dir, uid, gid)
        os.chmod(Config.profiles_dir, 0o700)

        # configure logging
        logger = logging.getLogger('ebpH')
        logger.setLevel(Config.verbosity)

        handler = logging.handlers.WatchedFileHandler(Config.logfile)
        handler.setLevel(Config.verbosity)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        formatter.datefmt = '%Y-%m-%d %H:%M:%S'
        handler.setFormatter(formatter)

        logger.addHandler(handler)
