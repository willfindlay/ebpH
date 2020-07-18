"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    ebpH Copyright (C) 2019-2020  William Findlay 
    pH   Copyright (C) 1999-2003 Anil Somayaji and (C) 2008 Mario Van Velzen

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

    Provides serveral constants for ebpH.

    2020-Jul-13  William Findlay  Created this.
"""

import os
from argparse import Namespace

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

# Allowed LFC count before resetting training data
TOLERIZE_LIMIT = 12

# Time in nanoseconds that a profile must remain frozen in order to become normal
NORMAL_WAIT = 1000000000 * 60 * 60 * 24 * 7 # 1 week
#NORMAL_WAIT = 1000000000 * 60 * 10 # 10 minutes
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

        # Length of ALF
        'EBPH_LOCALITY_WIN': 128,

        # The empty system call
        'EBPH_EMPTY': 9999,
        }

LOG_DIR = '/var/log/ebpH'

PIDFILE = '/run/ebpH.pid'

EBPH_DATA_DIR = '/var/lib/ebpH/profiles'

EBPH_PORT = 1337

PROFILE_SAVE_INTERVAL = 10000

TICK_SLEEP = 0.1


def init(args: Namespace) -> None:
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
