import os

from ebph.utils import project_path

# Root directory of ebpH
EBPH_DIR = project_path('ebph')
# Path to BPF source directory
BPF_DIR = project_path('ebph/bpf')
# Path to BPF source code
BPF_PROGRAM_C = project_path('ebph/bpf/bpf_program.c')

# Path to libebph.so
LIBEBPH = project_path('ebph/libebph/bin/libebph.so')

# train_count / (train_count - last_mod_count) must exceed
# NORMAL_FACTOR / NORMAL_FACTOR_DEN for a profile to become normal
NORMAL_FACTOR = 128
NORMAL_FACTOR_DEN = 32

# Number of allowed anomalies before a profile is no longer normal
ANOMALY_LIMIT = 30

# Time in nanoseconds that a profile must remain frozen in order to become normal
#NORMAL_WAIT = 1000000000 * 60 * 60 * 24 * 7 # 1 week
NORMAL_WAIT = 1000000000 * 60 * 10 # 10 minutes
#NORMAL_WAIT = 1000000000 * 30 # 30 seconds

PATH_MAX = 4096

# Compiler defines used in BPF program
BPF_DEFINES = {
        # Maximum number of active profiles
        'EBPH_MAX_PROFILES': 10240,
        # Maximum number of active processes at a given time
        'EBPH_MAX_PROCESSES': 10240,

        # Number of system calls
        'EBPH_NUM_SYSCALLS': 450,

        # Length of a sequence
        'EBPH_SEQLEN': 9,
        # Number of frames in sequence stack
        'EBPH_SEQSTACK_FRAMES': 2,

        # The empty system call
        'EBPH_EMPTY': 9999,

        # Time in nanoseconds that a profile must remain frozen in order to
        # become normal
        #'EBPH_NORMAL_WAIT': (1000000000 * 60 * 60 * 24 * 7), # 1 week
        #'EBPH_NORMAL_WAIT': (1000000000 * 60 * 10), # 10 minutes
        'EBPH_NORMAL_WAIT': (1000000000 * 30), # 30 seconds

        'EBPH_ANOMALY_LIMIT': 30,
        }

LOG_DIR = '/var/log/ebpH'

PIDFILE = '/run/ebpH.pid'

EBPH_DATA_DIR = '/var/lib/ebpH/profiles'

EBPH_PORT = 1337

PROFILE_SAVE_INTERVAL = 10000

TICK_SLEEP = 0.1


def init(args):
    """
    Perform basic setup.
    """
    # Set log file location
    global LOGFILE
    LOGFILE = os.path.join(LOG_DIR, 'ebph.log')

    # Make working_directory or set permissions of existing working_directory
    try:
        os.makedirs(EBPH_DATA_DIR, mode=0o700, exist_ok=True)
    except OSError:
        os.chmod(EBPH_DATA_DIR, mode=0o700)

    # Make policy_directory or set permissions of existing policy_directory
    try:
        os.makedirs(LOG_DIR, mode=0o755, exist_ok=True)
    except OSError:
        os.chmod(LOG_DIR, mode=0o755)

    from ebph.logger import setup_logger
    setup_logger(args)

    # Make pidfile parent directory
    os.makedirs(os.path.dirname(PIDFILE), exist_ok=True)
