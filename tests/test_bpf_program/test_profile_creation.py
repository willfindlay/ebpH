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

from ebph.bpf_program import BPFProgram
from ebph.utils import which, calculate_profile_key, project_path

def test_one_profile(bpf_program: BPFProgram, caplog):
    ls = which('ls')
    # There should be one profile after this
    subprocess.Popen(ls).wait()

    assert len(bpf_program.bpf['profiles']) >= 1

    # Make sure we can look up the profile by its key
    profile_key = calculate_profile_key(ls)
    bpf_program.bpf['profiles'][ct.c_uint64(profile_key)]
    # Make sure the profile has the correct name associated with it
    bpf_program.on_tick()
    assert bpf_program.profile_key_to_exe[profile_key] in ['ls', ls]

def test_multiple_profiles(bpf_program: BPFProgram, caplog):
    ls = which('ls')
    ps = which('ps')

    # There should be one profile after this
    subprocess.Popen(ls).wait()

    assert len(bpf_program.bpf['profiles']) >= 1

    # There should be two profiles after this
    subprocess.Popen(ps).wait()

    assert len(bpf_program.bpf['profiles']) >= 2

    # Make sure we can look up the profile by its key
    profile_key = calculate_profile_key(ls)
    bpf_program.bpf['profiles'][ct.c_uint64(profile_key)]
    # Make sure the profile has the correct name associated with it
    bpf_program.on_tick()
    assert bpf_program.profile_key_to_exe[profile_key] in ['ls', ls]

    # Make sure we can look up the profile by its key
    profile_key = calculate_profile_key(ps)
    bpf_program.bpf['profiles'][ct.c_uint64(profile_key)]
    # Make sure the profile has the correct name associated with it
    bpf_program.on_tick()
    assert bpf_program.profile_key_to_exe[profile_key] in ['ps', ps]

def test_sample_workload(bpf_program: BPFProgram, caplog):
    sample_workload = project_path('tests/driver/sample_workload.sh')
    subprocess.Popen(sample_workload).wait()

    # Profiles shold now include the following:
    profile_names = ['bash', 'ls', 'wc', 'ps', 'cat', 'echo', 'grep']
    profile_locations = [which(n) for n in profile_names]

    assert len(bpf_program.bpf['profiles']) >= 7

    bpf_program.on_tick()
    for n, p in zip(profile_names, profile_locations):
        # Make sure we can look up the profile by its key
        profile_key = calculate_profile_key(p)
        bpf_program.bpf['profiles'][ct.c_uint64(profile_key)]
        # Make sure the profile has the correct name associated with it
        assert bpf_program.profile_key_to_exe[profile_key] in [n, p]

