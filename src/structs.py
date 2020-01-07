# --------------------------------------- #
# WARNING WARNING WARNING WARNING WARNING #
# WARNING WARNING WARNING WARNING WARNING #
# --------------------------------------- #
# Keep in sync with bpf/bpf_program.h     #
#               and bpf/defs.h            #
# --------------------------------------- #
# WARNING WARNING WARNING WARNING WARNING #
# WARNING WARNING WARNING WARNING WARNING #
# --------------------------------------- #

import ctypes as ct

from utils import to_json_bytes
import base64

EBPH_FILENAME_LEN = 128
EBPH_NUM_SYSCALLS = 450
EBPH_LOOKAHEAD_ARRAY_SIZE = EBPH_NUM_SYSCALLS * EBPH_NUM_SYSCALLS

c_u8       = ct.c_uint8
c_u16      = ct.c_ushort
c_u32      = ct.c_ulong
c_u64      = ct.c_ulonglong
c_char     = ct.c_byte
c_int      = ct.c_int
c_long     = ct.c_long
c_longlong = ct.c_longlong

class EBPHProfile(ct.Structure):
    _fields_ = [
            ('frozen', c_u8),
            ('normal', c_u8),
            ('normal_time', c_u64),
            ('normal_count', c_u64),
            ('last_mod_count', c_u64),
            ('train_count', c_u64),
            ('anomalies', c_u64),
            ('flags', c_u8 * EBPH_LOOKAHEAD_ARRAY_SIZE),
            ('key', c_u64),
            ('comm', c_char * EBPH_FILENAME_LEN),
            ]

    def serialize(self):
        d = {
            'frozen': self.frozen,
            'normal': self.normal,
            'normal_time': self.normal_time,
            'normal_count': self.normal_count,
            'last_mod_count': self.last_mod_count,
            'train_count': self.train_count,
            'anomalies': self.anomalies,
            'flags': bytes(self.flags),
            'key': self.key,
            'comm': bytes(self.comm),
                }
        return to_json_bytes(d)

e = EBPHProfile()
print(e.serialize(), len(e.serialize()))
