import os
import subprocess
import ctypes as ct
import time
from random import randint

from ebph.bpf_program import BPFProgram
from ebph.utils import which, calculate_profile_key
from ebph.structs import EBPH_SETTINGS

def test_change_settings(bpf_program: BPFProgram, caplog):
    for setting in EBPH_SETTINGS:
        for _ in range(1000):
            value = randint(0, 2 ** 64 - 1)
            bpf_program.change_setting(setting, value)
            assert bpf_program.get_setting(setting) == value

def test_invalid_settings(bpf_program: BPFProgram, caplog):
    for setting in EBPH_SETTINGS:
        for _ in range(1000):
            original_value = bpf_program.get_setting(setting)
            value = randint(-(2 ** 64 - 1), -1)
            assert bpf_program.change_setting(setting, value) < 0
            assert bpf_program.get_setting(setting) == original_value
