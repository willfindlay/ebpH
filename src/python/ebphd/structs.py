# ebpH --  An eBPF intrusion detection program.
# -------  Monitors system call patterns and detect anomalies.
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
# Anil Somayaji (soma@scs.carleton.ca)
#
# Based on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# USAGE: ebphd <COMMAND>
#
# Licensed under GPL v2 License

# **************************************** #
#               WARNING!!!!!               #
#      Keep this in sync with ebpH.h       #
#             AT ALL TIMES!!               #
# **************************************** #

import ctypes as ct

EBPH_FILENAME_LEN = 128

class ebpH_executable(ct.Structure):
    _fields_ = [('key', ct.c_ulonglong),
            ('comm', ct.c_char * EBPH_FILENAME_LEN)]

class ebpH_pid_assoc(ct.Structure):
    _fields_ = [('pid', ct.c_ulong),
            ('e', ebpH_executable)]
