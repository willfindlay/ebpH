import os

from ebph.utils import project_path

BPF_DIR = project_path('ebph/bpf')
BPF_PROGRAM_C = project_path('ebph/bpf/bpf_program.c')

BPF_DEFINES = {
        'EBPH_MAX_PROFILES': 10240,
        'EBPH_MAX_PROCESSES': 10240,
        'EBPH_NUM_SYSCALLS': 450,
        'EBPH_SEQSTACK_FRAMES': 2,
        'EBPH_SEQLEN': 9,
        'EBPH_EMPTY': 9999,
        # One week in nanoseconds
        #'EBPH_NORMAL_WAIT': (1000000000 * 60 * 60 * 24 * 7),
        'EBPH_NORMAL_WAIT': (10),
        'EBPH_NORMAL_FACTOR': 128,
        'EBPH_NORMAL_FACTOR_DEN': 32,
        'EBPH_ANOMALY_LIMIT': 30,
        }

LOGDIR = '/var/log/ebpH'
LOGFILE = os.path.join(LOGDIR, 'ebph.log')

PROFILE_SAVE_INTERVAL = 10000

TICK_SLEEP = 0.1
