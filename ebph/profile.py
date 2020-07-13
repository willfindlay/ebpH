from pprint import pformat
import ctypes as ct
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
        (
            'train',
            ct.c_uint8
            * defs.BPF_DEFINES['EBPH_NUM_SYSCALLS']
            * defs.BPF_DEFINES['EBPH_NUM_SYSCALLS'],
        ),
        (
            'test',
            ct.c_uint8
            * defs.BPF_DEFINES['EBPH_NUM_SYSCALLS']
            * defs.BPF_DEFINES['EBPH_NUM_SYSCALLS'],
        ),
    )

    def _asdict(self) -> dict:
        return {field[0]: getattr(self, field[0]) for field in self._fields_}

    def __str__(self):
        return pformat((self.__class__.__name__, self._asdict()))

    @classmethod
    def from_bpf(
        cls,
        bpf: BPF,
        profile_key: int,
        train_key_cache: Dict[int, List['Key']] = None,
        test_key_cache: Dict[int, List['Key']] = None,
    ) -> 'EBPHProfileStruct':
        profile = EBPHProfileStruct()
        profile.magic = calculate_profile_magic()
        profile.profile_key = profile_key

        try:
            bpf_profile = bpf['profiles'][ct.c_uint64(profile_key)]
        except KeyError:
            raise KeyError('Profile does not exist in BPF map')

        profile.status = bpf_profile.status
        profile.anomaly_count = bpf_profile.anomaly_count
        profile.train_count = bpf_profile.train_count
        profile.last_mod_count = bpf_profile.last_mod_count
        profile.sequences = bpf_profile.sequences
        profile.normal_time = bpf_profile.normal_time
        profile.count = bpf_profile.count

        # TODO: cache this when saving all profiles so that we don't need
        # to iterate over ALL keys
        for k, v in bpf['training_data'].iteritems():
            if k.profile_key != profile.profile_key:
                continue
            curr = k.curr
            ct.memmove(profile.train[curr], v.prev, ct.sizeof(v.prev))

        # TODO: cache this when saving all profiles so that we don't need
        # to iterate over ALL keys
        for k, v in bpf['testing_data'].iteritems():
            if k.profile_key != profile.profile_key:
                continue
            curr = k.curr
            ct.memmove(profile.test[curr], v.prev, ct.sizeof(v.prev))

        return profile
