import os, sys
import stat
import pwd
import grp
import time
import gzip
import logging
from logging import handlers as handlers

import config
from utils import setup_dir, read_chunks

class EBPHRotatingFileHandler(handlers.TimedRotatingFileHandler):
    """
    Rotates log files either when they have reached the specified
    time or when they have reached the specified size. Keeps
    backupCount many backups.

    This class uses camel casing because that's what the logging module uses.
    """
    def __init__(self, filename, maxBytes=0, backupCount=0, encoding=None,
            delay=0, when='h', interval=1, utc=False):
        handlers.TimedRotatingFileHandler.__init__(self, filename, when,
                interval, backupCount, encoding, delay, utc)
        self.maxBytes = maxBytes
        self.suffix = "%Y-%m-%d_%H-%M-%S"

        def rotator(source, dest):
            dest = f'{dest}.gz'
            try:
                os.unlink(dest)
            except FileNotFoundError:
                pass
            with open(source, 'r') as sf, gzip.open(dest ,'ab') as df:
                for chunk in read_chunks(sf):
                    df.write(chunk.encode('utf-8'))
            try:
                os.unlink(source)
            except FileNotFoundError:
                pass

        self.rotator=rotator

    def shouldRollover(self, record):
        """
        Overload shouldRollover method from base class.

        Does file exceed size limit or have we exceeded time limit?
        """
        if self.stream is None:
            self.stream = self._open()
        if self.maxBytes > 0:
            msg = f'{self.format(record)}\n'
            self.stream.seek(0, 2)
            if self.stream.tell() + len(msg) >= self.maxBytes:
                return 1
        t = int(time.time())
        if t >= self.rolloverAt:
            return 1
        return 0

def setup_logger(args):
    # Get UID and GID of root
    uid = pwd.getpwnam("root").pw_uid
    gid = grp.getgrnam("root").gr_gid

    # Setup logdir
    setup_dir(config.logdir)

    # Setup logfile
    try:
        os.chown(config.logfile, uid, gid)
    except FileNotFoundError:
        pass

    # Setup data dir and make sure permissions are correct
    setup_dir(config.ebph_data_dir)
    os.chown(config.ebph_data_dir, uid, gid)
    os.chmod(config.ebph_data_dir, 0o700 | stat.S_ISVTX)

    # Setup profiles dir and make sure permissions are correct
    setup_dir(config.profiles_dir)
    os.chown(config.profiles_dir, uid, gid)
    os.chmod(config.profiles_dir, 0o700)

    # Configure logging
    formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
    formatter.datefmt = '%Y-%m-%d %H:%M:%S'

    if args.debug:
        config.verbosity = logging.DEBUG
    logger = logging.getLogger('ebph')
    logger.setLevel(config.verbosity)

    # Create and add handler
    # TODO: change this to allow configurable sizes, times, backup counts
    handler = EBPHRotatingFileHandler(
        config.logfile,
        maxBytes=(1024**3),
        backupCount=5,
        when='d',
        interval=21
    )
    handler.setLevel(config.verbosity)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Configure newseq logging
    #newseq_logger = logging.getLogger('newseq')
    #newseq_logger.setLevel(config.verbosity)

    #new_seq_handler = logging.handlers.WatchedFileHandler(config.newseq_logfile)
    #new_seq_handler.setLevel(config.verbosity)
    #new_seq_handler.setFormatter(formatter)
    #newseq_logger.addHandler(new_seq_handler)

    # Handle nolog argument
    if args.nolog:
        # create and configure a handler for stderr
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(config.verbosity)
        logger.addHandler(stream_handler)
        #newseq_logger.addHandler(stream_handler)

        # set formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
        formatter.datefmt = '%Y-%m-%d %H:%M:%S'
        stream_handler.setFormatter(formatter)

        # disable file handlers
        logger.handlers = [h for h in logger.handlers if not isinstance(h, EBPHRotatingFileHandler)]
        #newseq_logger.handlers = [h for h in logger.handlers if not isinstance(h, logging.handlers.WatchedFileHandler)]

def get_logger(name='ebph'):
    return logging.getLogger(name)
