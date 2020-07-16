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

    Test profile creation.

    2020-Jul-16  William Findlay  Created this.
"""

import os
import subprocess
import ctypes as ct
import time

from ebph.structs import EBPH_SETTINGS, EBPH_PROFILE_STATUS
from ebph.bpf_program import BPFProgram
from ebph.utils import which, calculate_profile_key, project_path, ns_to_str

def test_freeze(bpf_program: BPFProgram, caplog):
    hello = project_path('tests/driver/hello')

    bpf_program.change_setting(EBPH_SETTINGS.NORMAL_WAIT, 2 ** 60)

    for _ in range(1000):
        subprocess.Popen(hello, stdout=subprocess.DEVNULL).wait()
        bpf_program.on_tick()

    assert len(bpf_program.bpf['profiles']) >= 1

    profile_key = calculate_profile_key(hello)
    profile = bpf_program.get_profile(profile_key)

    assert profile.status & EBPH_PROFILE_STATUS.FROZEN
