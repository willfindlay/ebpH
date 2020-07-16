"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    Copyright (C) 2019-2020  William Findlay

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

    Defines several structs and enums for interacting with the BPF program.

    2020-Jul-13  William Findlay  Created this.
"""

import os
from pprint import pformat
import ctypes as ct
from enum import IntEnum, IntFlag, unique, auto
from typing import List, Dict

from bcc import BPF

from ebph.logger import get_logger
from ebph import defs

logger = get_logger()


def calculate_profile_magic():
    from hashlib import sha256
    from ebph.version import __version__

    __version__ = '0.2.0'

    version = __version__.encode('ascii')

    return int(sha256(version).hexdigest(), 16) & 0xFFFF_FFFF_FFFF_FFFF


@unique
class EBPH_PROFILE_STATUS(IntFlag):
    TRAINING = 0x1
    FROZEN = 0x2
    NORMAL = 0x4


@unique
class EBPH_SETTINGS(IntEnum):
    MONITORING = 0
    LOG_SEQUENCES = auto()
    NORMAL_WAIT = auto()
    NORMAL_FACTOR = auto()
    NORMAL_FACTOR_DEN = auto()
    ANOMALY_LIMIT = auto()


class EBPHProfileDataStruct(ct.Structure):
    _fields_ = (
        (
            'flags',
            ct.c_uint8 * (defs.BPF_DEFINES['EBPH_NUM_SYSCALLS']
            * defs.BPF_DEFINES['EBPH_NUM_SYSCALLS']),
        ),
    )

class EBPHProfileStruct(ct.Structure):
    _fields_ = (
        ('magic', ct.c_uint64),
        ('profile_key', ct.c_uint64),
        ('status', ct.c_uint8),
        ('anomaly_count', ct.c_uint64),
        ('train_count', ct.c_uint64),
        ('last_mod_count', ct.c_uint64),
        ('sequences', ct.c_uint64),
        ('normal_time', ct.c_uint64),
        ('count', ct.c_uint64),
        ('train', EBPHProfileDataStruct),
        ('test', EBPHProfileDataStruct),
        ('exe', ct.c_char * defs.PATH_MAX),
    )

    def _asdict(self) -> dict:
        return {field[0]: getattr(self, field[0]) for field in self._fields_}

    def __str__(self):
        return pformat((self.__class__.__name__, self._asdict()))

    @classmethod
    def from_bpf(cls, bpf: BPF, exe: bytes, profile_key: int,) -> 'EBPHProfileStruct':
        profile = EBPHProfileStruct()
        profile.magic = calculate_profile_magic()
        profile.profile_key = profile_key
        profile.exe = exe

        try:
            bpf_profile = bpf['profiles'][ct.c_uint64(profile_key)]
        except (KeyError, IndexError):
            raise KeyError('Profile does not exist in BPF map')

        profile.status = bpf_profile.status
        profile.anomaly_count = bpf_profile.anomaly_count
        profile.train_count = bpf_profile.train_count
        profile.last_mod_count = bpf_profile.last_mod_count
        profile.sequences = bpf_profile.sequences
        profile.normal_time = bpf_profile.normal_time
        profile.count = bpf_profile.count

        try:
            # Look up value
            train = bpf['training_data'][ct.c_uint64(profile_key)]
            # Copy values over
            if not ct.memmove(ct.addressof(profile.train), ct.addressof(train), ct.sizeof(profile.train)):
                raise RuntimeError('Failed to memmove training data!')
        except (KeyError, IndexError):
            pass

        try:
            # Look up value
            test = bpf['testing_data'][ct.c_uint64(profile_key)]
            # Copy values over
            if not ct.memmove(ct.addressof(profile.test), ct.addressof(test), ct.sizeof(profile.test)):
                raise RuntimeError('Failed to memove testing data!')
        except (KeyError, IndexError):
            pass

        return profile

    def load_into_bpf(self, bpf: BPF):
        # Get leaf
        bpf_profile = bpf['profiles'].Leaf()
        # Set values
        bpf_profile.status = self.status
        bpf_profile.anomaly_count = self.anomaly_count
        bpf_profile.train_count = self.train_count
        bpf_profile.last_mod_count = self.last_mod_count
        bpf_profile.sequences = self.sequences
        bpf_profile.normal_time = self.normal_time
        bpf_profile.count = self.count
        # Update map
        bpf['profiles'][ct.c_uint64(self.profile_key)] = bpf_profile

        # Get leaf
        train = bpf['training_data'].Leaf()
        # Copy values over
        if not ct.memmove(ct.addressof(train), ct.addressof(self.train), ct.sizeof(self.train)):
            raise RuntimeError('Failed to memmove training data!')
        # Update map
        bpf['training_data'][ct.c_uint64(self.profile_key)] = train

        # Get leaf
        test = bpf['testing_data'].Leaf()
        # Copy values over
        if not ct.memmove(ct.addressof(test), ct.addressof(self.test), ct.sizeof(self.test)):
            raise RuntimeError('Failed to memmove testing data!')
        # Update map
        bpf['testing_data'][ct.c_uint64(self.profile_key)] = test
