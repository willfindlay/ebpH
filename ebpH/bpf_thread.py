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
from PySide2.QtCore import Signal

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

# load a bpf program from a file
def load_bpf(code):
    with open(code, "r") as f:
        text = f.read()

    return text

class BPFThread(QThread):
    def __init__(self, parent=None):
        QThread.__init__(self, parent)
        self.exiting = False
        self.profiles = 0

    # save profiles to disk
    def save_profiles(self):
        profile_hash = self.bpf["profile"]
        test_hash    = self.bpf["test_data"]
        train_hash   = self.bpf["train_data"]

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

        if not self.exiting:
            self.sig_profiles_saved.emit()

    # load profiles from disk
    def load_profiles(self):
        # run the profile_loader which is registered with a uretprobe
        subprocess.run([LOADER_PATH])

    # --- Signals ---
    sig_event            = Signal(str)
    sig_warning          = Signal(str)
    sig_error            = Signal(str)
    sig_events           = Signal(list)
    sig_stats            = Signal(int, int, int, int, int)
    sig_can_exit         = Signal(bool)
    sig_profiles_saved   = Signal()

    # --- Control Flow ---
    # called when the thread is started
    def run(self):
        def on_profile_create(cpu, data, size):
            event = self.bpf["profile_create_event"].event(data)
            s = f"Profile {event.key} created."
            self.sig_event.emit(s)

        def on_profile_load(cpu, data, size):
            event = self.bpf["profile_load_event"].event(data)
            s = f"Profile {event.key} loaded."
            self.sig_event.emit(s)

        def on_profile_assoc(cpu, data, size):
            event = self.bpf["profile_assoc_event"].event(data)
            s = f"Profile {event.key} associated with PID {event.pid}."
            self.sig_event.emit(s)

        def on_profile_disassoc(cpu, data, size):
            event = self.bpf["profile_disassoc_event"].event(data)
            s = f"Profile {event.key} has been disassociated from PID {event.pid}."
            self.sig_event.emit(s)

        def on_profile_copy(cpu, data, size):
            event = self.bpf["profile_copy_event"].event(data)
            s = f"Profile {event.key} copied from PPID {event.ppid} to PID {event.pid}."
            self.sig_event.emit(s)

        def on_anomaly(cpu, data, size):
            event = self.bpf["anomaly_event"].event(data)
            s = " ".join(["Profile"])
            self.sig_warning.emit(s)

        self.sig_can_exit.emit(False)
        self.exiting = False

        if not os.path.exists(PROFILE_DIR):
            os.makedirs(PROFILE_DIR)

        # read BPF embedded C from bpf.c
        text = load_bpf("./bpf.c")

        # compile ebpf code
        self.bpf = BPF(text=text)
        # register callback to load profiles
        self.bpf.attach_uretprobe(name=LOADER_PATH, sym='load_profile', fn_name='pH_load_profile')
        self.bpf.attach_kretprobe(event='do_open_execat', fn_name='pH_on_do_open_execat')

        # register perf outputs
        self.bpf["profile_create_event"].open_perf_buffer(on_profile_create)
        self.bpf["profile_load_event"].open_perf_buffer(on_profile_load)
        self.bpf["profile_assoc_event"].open_perf_buffer(on_profile_assoc)
        self.bpf["profile_disassoc_event"].open_perf_buffer(on_profile_disassoc)
        self.bpf["profile_copy_event"].open_perf_buffer(on_profile_copy)
        self.bpf["anomaly_event"].open_perf_buffer(on_anomaly)

        # load in any profiles
        self.load_profiles()

        while True:
            # update the hashmap of sequences
            self.bpf.perf_buffer_poll(100)
            self.num_profiles = self.bpf["profiles"].values()[0].value
            self.num_syscalls = self.bpf["syscalls"].values()[0].value
            self.num_forks    = self.bpf["forks"].values()[0].value
            self.num_execves  = self.bpf["execves"].values()[0].value
            self.num_exits  = self.bpf["exits"].values()[0].value
            self.sig_stats.emit(self.num_profiles, self.num_syscalls, self.num_forks, self.num_execves, self.num_exits)

            # exit control flow
            if self.exiting:
                self.save_profiles()

                # clear the BPF hashmap
                #seq_hash.clear()
                #pro_hash.clear()
                self.bpf.cleanup()
                self.sig_warning.emit("Probe has been detached.")
                self.sig_can_exit.emit(True)
                break
