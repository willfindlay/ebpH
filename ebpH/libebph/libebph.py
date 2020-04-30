import os, sys
import ctypes as ct

from ebpH import defs
from ebpH.logger import get_logger

logger = get_logger()

try:
    libebph = ct.CDLL(defs.libebph)
    logger.info(f'Loaded {defs.libebph}')
except:
    raise Exception(f'Unable to load {defs.libebph}. Have you run make?')

commands = []

def add_command(command, argtypes):
    commands.append((command, argtypes))

def register_uprobes(bpf):
    for item in commands:
        command = item[0]
        argtypes = item[1]
        logger.info(command)
        getattr(libebph, command).argtypes = argtypes
        bpf.attach_uprobe(name=defs.libebph, sym=command, pid=os.getpid(), fn_name=command)
        logger.debug(f'Registered uprobe for {command}')

# ===============================================================
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# ===============================================================
# Keep in sync with libebph/libebph.c
# ===============================================================
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# ===============================================================

# Process commands
add_command('cmd_normalize_process', [ct.c_uint32])
add_command('cmd_tolerize_process',  [ct.c_uint32])

# Profile commands
add_command('cmd_normalize_profile', [ct.c_uint64])
add_command('cmd_tolerize_profile',  [ct.c_uint64])
add_command('cmd_reset_profile',     [ct.c_uint64])
