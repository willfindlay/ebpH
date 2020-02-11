
# ===============================================================
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# ===============================================================
# Keep in sync with src/bpf/bpf_program.h
# ===============================================================
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
# ===============================================================

import ctypes as ct

class EBPHProfileData(ct.Structure):
    _fields_ = [
            ('flags', ct.c_uint8),
            ('last_mod_count', ct.c_uint64),
            ('train_count', ct.c_uint64),
            ('normal_count', ct.c_uint64),
            ]

class EBPHProfile(ct.Structure):
    _fields_ = [
            (),
            ]
