# ebpH  An eBPF intrusion detection program. Monitors system call patterns and detect anomalies.
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
# Anil Somayaji (soma@scs.carleton.ca)
#
# Based on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# Licensed under GPL v2 License

# ===============================================================
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# ===============================================================
# Keep in sync with src/bpf/bpf_program.h
# ===============================================================
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# ===============================================================

import config
config.init()
import ctypes as ct

EBPH_NUM_SYSCALLS = config.bpf_params['EBPH_NUM_SYSCALLS']
EBPH_SEQLEN = 9
EBPH_SEQSTACK_SIZE = 6
EBPH_LOCALITY_WIN = 128
EBPH_FILENAME_LEN = 128

# Profiles below this line ----------------------------------------------------------

class EBPHProfileData(ct.Structure):
    """
    ctypes structure representing struct ebpH_profile_data from src/bpf/bpf_program.h

    This class MUST be kept in sync with src/bpf/bpf_program.h
    """
    _fields_ = [
            ('flags', (ct.c_uint8 * EBPH_NUM_SYSCALLS) * EBPH_NUM_SYSCALLS),
            ('last_mod_count', ct.c_uint64),
            ('train_count', ct.c_uint64),
            ('normal_count', ct.c_uint64),
            ]

class EBPHProfile(ct.Structure):
    """
    ctypes structure representing struct ebpH_profile from src/bpf/bpf_program.h

    This class MUST be kept in sync with src/bpf/bpf_program.h
    """
    _fields_ = [
            ('frozen', ct.c_uint8),
            ('normal', ct.c_uint8),
            ('normal_time', ct.c_uint64),
            ('anomalies', ct.c_uint64),
            ('train', EBPHProfileData),
            ('test', EBPHProfileData),
            ('key', ct.c_uint64),
            ('comm', ct.c_char * EBPH_FILENAME_LEN),
            ]

# Processes below this line ----------------------------------------------------------

class EBPHLocality(ct.Structure):
    """
    ctypes structure representing struct ebpH_locality from src/bpf/bpf_program.h

    This class MUST be kept in sync with src/bpf/bpf_program.h
    """
    _fields_ = [
            ('win', ct.c_uint8 * EBPH_LOCALITY_WIN),
            ('first', ct.c_uint32),
            ('total', ct.c_uint32),
            ('max', ct.c_uint32),
            ]

class EBPHSequence(ct.Structure):
    """
    ctypes structure representing struct ebpH_sequence from src/bpf/bpf_program.h

    This class MUST be kept in sync with src/bpf/bpf_program.h
    """
    _fields_ = [
            ('seq', ct.c_long * EBPH_SEQLEN),
            ('count', ct.c_uint8),
            ]

class EBPHSequenceStack(ct.Structure):
    """
    ctypes structure representing struct ebpH_sequence_stack from src/bpf/bpf_program.h

    This class MUST be kept in sync with src/bpf/bpf_program.h
    """
    _fields_ = [
            ('seq', EBPHSequence * EBPH_SEQSTACK_SIZE),
            ('top', ct.c_uint8),
            ('should_pop', ct.c_uint8),
            ]

class EBPHProcess(ct.Structure):
    """
    ctypes structure representing struct ebpH_process from src/bpf/bpf_program.h

    This class MUST be kept in sync with src/bpf/bpf_program.h
    """
    _fields_ = [
            ('alf', EBPHLocality),
            ('stack', EBPHSequenceStack),
            ('pid', ct.c_uint32),
            ('tid', ct.c_uint32),
            ('profile_key', ct.c_uint64),
            ('in_execve', ct.c_uint8),
            ]
