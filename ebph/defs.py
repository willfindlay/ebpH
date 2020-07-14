import os

from ebph.utils import project_path

# Root directory of ebpH
EBPH_DIR = project_path('ebph')
# Path to BPF source directory
BPF_DIR = project_path('ebph/bpf')
# Path to BPF source code
BPF_PROGRAM_C = project_path('ebph/bpf/bpf_program.c')

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

        # EBPH_NORMAL_FACTOR / EBPH_NORMAL_FACTOR_DEN sets a threshold of
        # stability before a profile can become normal
        'EBPH_NORMAL_FACTOR': 128,
        'EBPH_NORMAL_FACTOR_DEN': 32,

        # Number of allowed anomalies before a profile is no longer normal
        'EBPH_ANOMALY_LIMIT': 30,
        }

LOGDIR = '/var/log/ebpH'
LOGFILE = os.path.join(LOGDIR, 'ebph.log')

PIDFILE = '/run/ebpH.pid'

EBPH_DATA_DIR = '/var/log/ebpH'

EBPH_PORT = 1337

PROFILE_SAVE_INTERVAL = 10000

TICK_SLEEP = 0.1
