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
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2.QtCore import *
from colors import *
import globals

# load a bpf program from a file
def load_bpf(code):
    code = f"{os.path.dirname(__file__)}/{code}"
    with open(code, "r") as f:
        text = f.read()
    return text

# used in fetch profile
class ProfilePayload():
    def __init__(self, profile, test, train):
        self.profile = profile
        self.test = test
        self.train = train

class BPFWorker(QObject):
    # --- Signals ---
    sig_event            = Signal(str)
    sig_warning          = Signal(str)
    sig_error            = Signal(str)
    sig_events           = Signal(list)
    sig_stats            = Signal(int, int, int, int, int)
    sig_profile_created  = Signal()

    def __init__(self, parent=None):
        super(BPFWorker, self).__init__(parent)
        self.monitoring = False

        if not os.path.exists(globals.PROFILE_DIR):
            os.makedirs(globals.PROFILE_DIR)

    def save_profiles(self):
        profile_hash = self.bpf["profile"]
        test_hash    = self.bpf["test_data"]
        train_hash   = self.bpf["train_data"]

        profile_dict = dict([(k.value, v) for k, v in profile_hash.items()])
        test_dict = dict([(k.value, v) for k, v in test_hash.items()])
        train_dict = dict([(k.value, v) for k, v in train_hash.items()])

        for k in profile_dict:
            profile  = profile_dict[k]
            test     = test_dict[k]
            train    = train_dict[k]
            filename = str(profile.key)

            profile_path = os.path.join(globals.PROFILE_DIR, filename)

            # create path if it doesn't exist
            if not os.path.exists(os.path.dirname(profile_path)):
                try:
                    os.makedirs(os.path.dirname(profile_path))
                except OSError as exc: # Guard against race condition
                    if exc.errno != errno.EEXIST:
                        raise
            with open(profile_path, "w") as f:
                printb(b"".join([profile,test,train]),file=f,nl=0)
        self.sig_event.emit("Profiles saved successfully.")

    # load profiles from disk
    def load_profiles(self, profile=None):
        # run the profile_loader which is registered with a uretprobe
        if profile:
            subprocess.run([globals.LOADER_PATH, f"load {profile}"])
        else:
            subprocess.run([globals.LOADER_PATH, f"load-all"])

    # fetch a profile from BPF program and return it in the form of profile payload
    def fetch_profile(self, key):
        try:
            profile_hash = self.bpf["profile"]
            test_hash    = self.bpf["test_data"]
            train_hash   = self.bpf["train_data"]

            profile_dict = dict([(k.value, v) for k, v in profile_hash.items()])
            test_dict = dict([(k.value, v) for k, v in test_hash.items()])
            train_dict = dict([(k.value, v) for k, v in train_hash.items()])

            profile  = profile_dict[key]
            test     = test_dict[key]
            train    = train_dict[key]

            return ProfilePayload(profile, test, train)
        except:
            return None

    # return a list of profile payloads for all profiles
    def fetch_all_profiles(self):
        profile_hash = self.bpf["profile"]
        test_hash    = self.bpf["test_data"]
        train_hash   = self.bpf["train_data"]

        profile_dict = dict([(k.value, v) for k, v in profile_hash.items()])
        test_dict = dict([(k.value, v) for k, v in test_hash.items()])
        train_dict = dict([(k.value, v) for k, v in train_hash.items()])

        return [ProfilePayload(profile_dict[k], test_dict[k], train_dict[k]) for k in profile_dict]

    def register_perf_buffers(self):
        # profile has been created for the first time
        def on_profile_create(cpu, data, size):
            event = self.bpf["profile_create_event"].event(data)
            s = f"Profile {event.key} created."
            self.sig_event.emit(s)
            self.sig_profile_created.emit()
        self.bpf["profile_create_event"].open_perf_buffer(on_profile_create)

        # profile has been loaded for the first time
        def on_profile_load(cpu, data, size):
            event = self.bpf["profile_load_event"].event(data)
            s = f"Profile {event.key} ({event.comm.decode('utf-8')}) loaded."
            self.sig_event.emit(s)
            self.sig_profile_created.emit()
        self.bpf["profile_load_event"].open_perf_buffer(on_profile_load)

        # profile has been reloaded
        def on_profile_reload(cpu, data, size):
            event = self.bpf["profile_load_event"].event(data)
            s = f"Profile {event.key} ({event.comm.decode('utf-8')}) overwritten via load."
            self.sig_warning.emit(s)
        self.bpf["profile_reload_event"].open_perf_buffer(on_profile_reload)

        # profile has been associated with a PID
        def on_profile_assoc(cpu, data, size):
            event = self.bpf["profile_assoc_event"].event(data)
            s = f"Profile {event.key} associated with PID {event.pid}."
            self.sig_event.emit(s)
        self.bpf["profile_assoc_event"].open_perf_buffer(on_profile_assoc)

        # profile has been disasscoated from a PID
        def on_profile_disassoc(cpu, data, size):
            event = self.bpf["profile_disassoc_event"].event(data)
            s = f"Profile {event.key} has been disassociated from PID {event.pid}."
            self.sig_event.emit(s)
        self.bpf["profile_disassoc_event"].open_perf_buffer(on_profile_disassoc)

        # profile has been copied
        def on_profile_copy(cpu, data, size):
            event = self.bpf["profile_copy_event"].event(data)
            s = f"Profile {event.key} copied from PPID {event.ppid} to PID {event.pid}."
            self.sig_event.emit(s)
        self.bpf["profile_copy_event"].open_perf_buffer(on_profile_copy)

        # anomaly detected FIXME: not yet implemented
        def on_anomaly(cpu, data, size):
            event = self.bpf["anomaly_event"].event(data)
            s = f"Anomalous systemcall made by process {event.pid} associated with {event.comm.decode('utf-8')} ({event.profile_key})."
            self.sig_warning.emit(s)
        self.bpf["anomaly_event"].open_perf_buffer(on_anomaly)

        # generic warning and debug messages
        def on_error(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.sig_error.emit(s)
        self.bpf["pH_error"].open_perf_buffer(on_error)
        def on_warning(cpu, data, size):
            event = ct.cast(data, ct.c_char_p).value.decode('utf-8')
            s = f"{event}"
            self.sig_warning.emit(s)
        self.bpf["pH_warning"].open_perf_buffer(on_warning)
        def on_debug(cpu, data, size):
            event = self.bpf["output_number"].event(data)
            s = f"{event.n}"
            self.sig_warning.emit(s)
        self.bpf["output_number"].open_perf_buffer(on_debug)

    def start_monitoring(self):
        # read BPF embedded C from bpf.c
        text = load_bpf("bpf.c")
        text = text.replace("DEFS_H", globals.DEFS_H, 1)
        text = text.replace("PROFILES_H", globals.PROFILES_H, 1)

        # compile ebpf code
        self.bpf = BPF(text=text)
        self.register_perf_buffers()
        # register callback to load profiles
        self.bpf.attach_uretprobe(name=globals.LOADER_PATH, sym='load_profile', fn_name='pH_load_profile')
        self.bpf.attach_kretprobe(event='do_open_execat', fn_name='pH_on_do_open_execat')

        # load in any profiles
        self.load_profiles()
        self.tick()
        self.monitoring = True

    def stop_monitoring(self):
        self.save_profiles()
        self.bpf.cleanup()
        self.bpf = None
        self.monitoring = False
        self.sig_event.emit("Monitoring stopped.")

    def tick(self):
        try:
            self.bpf
        except:
            return
        if not self.monitoring:
            return
        # update the hashmap of sequences
        self.bpf.perf_buffer_poll(100)
        self.num_profiles = self.bpf["profiles"].values()[0].value
        self.num_syscalls = self.bpf["syscalls"].values()[0].value
        self.num_forks    = self.bpf["forks"].values()[0].value
        self.num_execves  = self.bpf["execves"].values()[0].value
        self.num_exits  = self.bpf["exits"].values()[0].value
        self.sig_stats.emit(self.num_profiles, self.num_syscalls, self.num_forks, self.num_execves, self.num_exits)
