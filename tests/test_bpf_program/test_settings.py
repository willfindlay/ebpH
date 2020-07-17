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

    Test changing BPF program settings.

    2020-Jul-16  William Findlay  Created this.
"""

import os
import subprocess
import ctypes as ct
import time
from random import randint

from ebph.bpf_program import BPFProgram
from ebph.utils import which, calculate_profile_key
from ebph.structs import EBPH_SETTINGS


def test_change_settings(bpf_program: BPFProgram, caplog):
    """
    Test getting and setting all ebpH settings.
    """
    for setting in EBPH_SETTINGS:
        for _ in range(100):
            value = randint(0, 2 ** 64 - 1)
            bpf_program.change_setting(setting, value)
            assert bpf_program.get_setting(setting) == value


def test_invalid_settings(bpf_program: BPFProgram, caplog):
    """
    Test getting and setting invalid ebpH settings.
    """
    for setting in EBPH_SETTINGS:
        for _ in range(100):
            original_value = bpf_program.get_setting(setting)
            value = randint(-(2 ** 64 - 1), -1)
            assert bpf_program.change_setting(setting, value) < 0
            assert bpf_program.get_setting(setting) == original_value
