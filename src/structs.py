
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
EBPH_LOOKAHEAD_ARRAY_SIZE = EBPH_NUM_SYSCALLS * EBPH_NUM_SYSCALLS
EBPH_FILENAME_LEN = 128

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
