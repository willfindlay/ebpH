import logging
import os, sys
import pwd
import grp
import stat

from ebpH.utils import path
from ebpH.config import config, parse_time

# Configurable values below this line =============================================

# Verbosity level for logging
# Possible values: logging.CRITICAL, logging.ERROR, logging.WARNING,
#                  logging.INFO,     logging.DEBUG
verbosity = config['Logging'].get('log_level')
verbosity = logging.INFO if verbosity == 'info' else logging.DEBUG if verbosity == 'debug' \
        else logging.ERROR if verbosity == 'quiet' else logging.INFO

# How long ebpH should sleep between ticks in seconds?
# Lower values imply higher CPU usage
# Recommended value is around 1 second
ticksleep = config['Daemon'].getfloat('tick_sleep', 0.1)

# How many ticks between automatic saves
saveinterval = config['Daemon'].getint('save_interval')

# When attempting to stop the daemon, how long do we wait before giving up?
killtimeout = parse_time(config['Misc'].get('killtimeout', '20s'))

# Default to logging new sequences?
log_new_sequences = config['Logging'].getboolean('log_new_sequences', False)
#log_new_sequences = True

# BPFProgram constants dictionary
bpf_params = {
        'EBPH_NORMAL_FACTOR': config['BPF'].getint('normal_factor', 128),
        'EBPH_NORMAL_FACTOR_DEN': config['BPF'].getint('normal_factor_den', 32),
        'EBPH_NORMAL_WAIT': int(parse_time(config['BPF'].get('normal_wait', '1w')) * 1e9),
        'EBPH_ANOMALY_LIMIT': config['BPF'].getint('anomaly_limit', 30),
        'EBPH_TOLERIZE_LIMIT': config['BPF'].getint('tolerize_limit', 12),
        'EBPH_PROFILES_TABLE_SIZE': config['BPF'].getint('profiles_table_size', 10240),
        'EBPH_PROCESSES_TABLE_SIZE': config['BPF'].getint('processes_table_size', 4194304),
        'EBPH_NUM_SYSCALLS': config['BPF'].getint('num_syscalls', 450),
        'EBPH_LOCALITY_WIN': config['BPF'].getint('locality_win', 128),
        }

# Port to run the flask server on
port = config['Daemon'].getint('port', 1000)

# Non-configurable values below this line =========================================

# Location where pidfile should be stored
rundir = '/run'
# Location where log files should be saved
logdir = '/var/log/ebpH'
# ebpH data directory
ebph_data_dir =  '/var/lib/ebpH'

project_path = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
profiles_dir = os.path.join(ebph_data_dir, 'profiles')
bpf_program = path('ebpH/bpf/bpf_program.c')
libebph = path('ebpH/libebph/__libebph.so')
pidfile = os.path.join(rundir, 'ebph.pid')
logfile = os.path.join(logdir, 'ebph.log')

def init():
    """
    Perform first time setup for some of the values here.
    This is especially important to set up important directories.
    """
    from ebpH.utils import setup_dir

    # Get UID and GID of root
    uid = pwd.getpwnam("root").pw_uid
    gid = grp.getgrnam("root").gr_gid

    # Setup data dir and make sure permissions are correct
    setup_dir(ebph_data_dir)
    os.chown(ebph_data_dir, uid, gid)
    os.chmod(ebph_data_dir, 0o700 | stat.S_ISVTX)

    # Setup profiles dir and make sure permissions are correct
    setup_dir(profiles_dir)
    os.chown(profiles_dir, uid, gid)
    os.chmod(profiles_dir, 0o700)

    # Setup logdir
    setup_dir(logdir)

    # Setup logfile
    try:
        os.chown(logfile, uid, gid)
    except FileNotFoundError:
        pass


