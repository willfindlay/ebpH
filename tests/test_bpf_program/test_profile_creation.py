import os
import subprocess
import ctypes as ct
import time

from ebph.bpf_program import BPFProgram
from ebph.utils import which, calculate_profile_key

def test_one_profile(bpf_program: BPFProgram, caplog):
    ls = which('ls')
    # There should be one profile after this
    subprocess.Popen(ls).wait()

    assert len(bpf_program.bpf['profiles']) == 1

    # There should still only be one profile after this
    subprocess.Popen(ls).wait()
    subprocess.Popen(ls).wait()
    subprocess.Popen(ls).wait()
    subprocess.Popen(ls).wait()

    assert len(bpf_program.bpf['profiles']) == 1

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

    assert len(bpf_program.bpf['profiles']) == 1

    # There should be two profiles after this
    subprocess.Popen(ps).wait()

    assert len(bpf_program.bpf['profiles']) == 2

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
