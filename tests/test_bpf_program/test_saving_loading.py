"""
    ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
    ebpH Copyright (C) 2019-2020  William Findlay 
    pH   Copyright (C) 1999-2003 Anil Somayaji and (C) 2008 Mario Van Velzen

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

    Test saving and loading.

    2020-Jul-16  William Findlay  Created this.
"""

import os
import subprocess
import ctypes as ct
import time

from ebph.bpf_program import BPFProgram
from ebph.utils import which, calculate_profile_key, project_path
from ebph.structs import EBPHProfileStruct


def test_save_then_load_hello(bpf_program: BPFProgram, caplog):
    """
    Make sure that saving, erasing, and then loading one profile
    works as expected.
    """
    hello = project_path('tests/driver/hello')
    subprocess.Popen(hello).wait()
    bpf_program.on_tick()

    assert len(bpf_program.bpf['profiles']) >= 1

    profile_key = calculate_profile_key(hello)

    profile_before = bpf_program.get_full_profile(profile_key)

    bpf_program.stop_monitoring()
    bpf_program.save_profiles()

    # Clear relevant profile data
    bpf_program.profile_key_to_exe.clear()
    assert not bpf_program.profile_key_to_exe
    bpf_program.bpf['profiles'].clear()
    assert len(bpf_program.bpf['profiles']) == 0
    bpf_program.bpf['training_data'].clear()
    assert len(bpf_program.bpf['training_data']) == 0
    bpf_program.bpf['testing_data'].clear()
    assert len(bpf_program.bpf['testing_data']) == 0

    bpf_program.load_profiles()
    bpf_program.start_monitoring()
    profile_key = calculate_profile_key(hello)

    assert len(bpf_program.bpf['profiles']) >= 1

    profile_after = bpf_program.get_full_profile(profile_key)

    assert profile_before == profile_after


def test_save_then_load_sample_workload(bpf_program: BPFProgram, caplog):
    """
    Make sure that saving, erasing, and then loading several profiles
    works as expected.
    """
    sample_workload = project_path('tests/driver/sample_workload.sh')
    subprocess.Popen(sample_workload).wait()
    bpf_program.on_tick()

    # Profiles shold now include the following:
    profile_names = ['bash', 'ls', 'wc', 'ps', 'cat', 'echo', 'grep']
    profile_locations = [which(n) for n in profile_names]
    profiles_keys = [calculate_profile_key(loc) for loc in profile_locations]
    profiles_before = [bpf_program.get_full_profile(key) for key in profiles_keys]

    assert len(bpf_program.bpf['profiles']) >= 7

    bpf_program.stop_monitoring()
    bpf_program.save_profiles()

    # Clear relevant profile data
    bpf_program.profile_key_to_exe.clear()
    assert not bpf_program.profile_key_to_exe
    bpf_program.bpf['profiles'].clear()
    assert len(bpf_program.bpf['profiles']) == 0
    bpf_program.bpf['training_data'].clear()
    assert len(bpf_program.bpf['training_data']) == 0
    bpf_program.bpf['testing_data'].clear()
    assert len(bpf_program.bpf['testing_data']) == 0

    bpf_program.load_profiles()
    bpf_program.start_monitoring()

    assert len(bpf_program.bpf['profiles']) >= 7

    profiles_after = [bpf_program.get_full_profile(key) for key in profiles_keys]

    for pb, pa in zip(profiles_before, profiles_after):
        assert pb == pa

    for n, p in zip(profile_names, profile_locations):
        # Make sure we can look up the profile by its key
        profile_key = calculate_profile_key(p)
        bpf_program.bpf['profiles'][ct.c_uint64(profile_key)]
        # Make sure the profile has the correct name associated with it
        assert bpf_program.profile_key_to_exe[profile_key] in [n, p]
