import os
import subprocess
import ctypes as ct
import time

from ebph.bpf_program import BPFProgram
from ebph.utils import which, calculate_profile_key, project_path

def test_save_then_load_sample_workload(bpf_program: BPFProgram, caplog):
    sample_workload = project_path('tests/driver/sample_workload.sh')
    subprocess.Popen(sample_workload).wait()

    # Profiles shold now include the following:
    profile_names = ['bash', 'ls', 'wc', 'ps', 'cat', 'echo', 'grep']
    profile_locations = [which(n) for n in profile_names]

    assert len(bpf_program.bpf['profiles']) == 7

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

    assert len(bpf_program.bpf['profiles']) == 7

    bpf_program.on_tick()
    for n, p in zip(profile_names, profile_locations):
        # Make sure we can look up the profile by its key
        profile_key = calculate_profile_key(p)
        bpf_program.bpf['profiles'][ct.c_uint64(profile_key)]
        # Make sure the profile has the correct name associated with it
        assert bpf_program.profile_key_to_exe[profile_key] in [n, p]

