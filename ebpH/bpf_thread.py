#! /usr/bin/env python3

# ebpH --  Monitor syscall sequences and detect anomalies
# Copyright 2019 Anil Somayaji (soma@scs.carleton.ca) and
# William Findlay (williamfindlay@cmail.carleton.ca)
#
# Based on Sasha Goldshtein's syscount
#  https://github.com/iovisor/bcc/blob/master/tools/syscount.py
#  Copyright 2017, Sasha Goldshtein.
# And on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# USAGE: ebpH.py
#
# Licensed under GPL v2 License

from time import sleep, strftime
import subprocess
import argparse
import textwrap
import errno
import itertools
import sys
import signal
import os
from bcc import BPF
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls
import ctypes as ct
from PySide2.QtCore import QThread

# directory in which profiles are stored
PROFILE_DIR = "/var/lib/pH/profiles"
# path of profile loader executable
LOADER_PATH = os.path.abspath("profile_loader")
# length of sequences
SEQLEN = 8

def print_sequences():
    # fetch BPF hashmap
    seq_hash = bpf["seq"]

    # print system time
    print()
    print("[%s]" % strftime("%H:%M:%S %p"))

    # print sequence for each inspected process
    for p, s in seq_hash.items():
        pid = p.value >> 32
        names = map(syscall_name, s.seq);
        calls = map(str, s.seq);

        # separator
        print()
        print("----------------------------------------------------------")
        print()

        # print the process and the sequence length
        print("%-8s %-8s" % ("PID","COUNT"))
        print("%-8d %-8s" % (pid, s.count));

        # list of sequences by "Call Name(Call Number),"
        print()
        print('Sequence:')
        arr = []
        for i,(call,name) in enumerate(zip(calls,names)):
            if i >= SEQLEN or i >= s.count:
                break;
            arr.append("%s(%s)" % (name.decode('utf-8'), call))
        print(textwrap.fill(", ".join(arr)))
        print()

# TODO: flesh this out... right now it just prints profile filenames
def print_profiles():
    # fetch hashmap
    profile_hash = bpf["profile"]

    for k, profile in profile_hash.items():
        print(k)

# save profiles to disk
def save_profiles():
    profile_hash = bpf["profile"]
    test_hash = bpf["test_data"]
    train_hash = bpf["train_data"]

    for profile, test, train in zip(profile_hash.values(), test_hash.values(), train_hash.values()):
        filename = str(profile.key)

        # get rid of slash if it is the first character
        if filename[0] == r'/':
            filename = filename[1:]
        profile_path = os.path.join(PROFILE_DIR, filename)

        # create path if it doesn't exist
        if not os.path.exists(os.path.dirname(profile_path)):
            try:
                os.makedirs(os.path.dirname(profile_path))
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        with open(profile_path, "w") as f:
            printb(b"".join([profile,test,train]),file=f,nl=0)

# load profiles from disk
def load_profiles():
    for dirpath, dirnames, files in os.walk(PROFILE_DIR):
        for f in files:
            profile_path = os.path.join(dirpath, f)
            # run the profile_loader which is registered with a uretprobe
            subprocess.run([LOADER_PATH,profile_path])

# load a bpf program from a file
def load_bpf(code):
    with open(code, "r") as f:
        text = f.read()

    return text


class BPFThread(QThread):
    def __init__(self, parent=None):
        QThread.__init__(self, parent)
        self.exiting = False

    def run(self):
        self.exiting = False

        if not os.path.exists(PROFILE_DIR):
            os.makedirs(PROFILE_DIR)

        # read BPF embedded C from bpf.c
        text = load_bpf("./bpf.c")

        # compile ebpf code
        bpf = BPF(text=text)
        # register callback to load profiles
        bpf.attach_uretprobe(name=LOADER_PATH, sym='load_profile', fn_name='pH_load_profile')
        bpf.attach_kretprobe(event='do_open_execat', fn_name='pH_on_do_open_execat')

        # load in any profiles
        load_profiles()

        while True:
            # update the hashmap of sequences
            #bpf.trace_print()
            sleep(1)

            # exit control flow
            if self.exiting:
                save_profiles()

                # clear the BPF hashmap
                seq_hash.clear()
                pro_hash.clear()

                print()
                print("Detaching...")
                self.terminate()
