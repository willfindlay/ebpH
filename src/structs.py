# --------------------------------------- #
# WARNING WARNING WARNING WARNING WARNING #
# WARNING WARNING WARNING WARNING WARNING #
# --------------------------------------- #
# Keep in sync with bpf/bpf_program.h !!! #
# --------------------------------------- #
# WARNING WARNING WARNING WARNING WARNING #
# WARNING WARNING WARNING WARNING WARNING #
# --------------------------------------- #

import ctypes as ct

c_u8       = ct.c_uint8
c_u16      = ct.c_ushort
c_u32      = ct.c_ulong
c_u64      = ct.c_ulonglong
c_char     = ct.c_byte
c_int      = ct.c_int
c_long     = ct.c_long
c_longlong = ct.c_longlong

class EBPHProfile(ct.Structure):
    def serialize(self):
        pass
