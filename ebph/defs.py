import os

from ebph.utils import project_path

BPF_DIR = project_path('ebph/bpf')
BPF_PROGRAM_C = project_path('ebph/bpf/bpf_program.c')

BPF_DEFINES = {
        }

LOGDIR = '/var/log/ebpH'
LOGFILE = os.path.join(LOGDIR, 'ebph.log')

PROFILE_SAVE_INTERVAL = 10000

TICK_SLEEP = 0.1
