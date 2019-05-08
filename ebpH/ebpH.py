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
# USAGE: ebpH.py <COMMAND>
#
# Licensed under GPL v3 License

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
from pprint import pprint

# directory in which profiles are stored
PROFILE_DIR = "/var/lib/pH/profiles"
# path of profile loader executable
LOADER_PATH = os.path.abspath("profile_loader")
# path of exe finder executable
EXE_FINDER_PATH = os.path.abspath("exe_finder")
# length of sequences
SEQLEN = 8

# signal handler
def signal_ignore(signal, frame):
    print()

def handle_errno(errstr):
    try:
        return abs(int(errstr))
    except ValueError:
        pass

    try:
        return getattr(errno, errstr)
    except AttributeError:
        raise argparse.ArgumentTypeError("couldn't map %s to an errno" % errstr)

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
        filename = profile.filename.decode('utf-8')
        print(filename)

# save profiles to disk
def save_profiles():
    profile_hash = bpf["profile"]
    test_hash = bpf["test_data"]
    train_hash = bpf["train_data"]

    for profile, test, train in zip(profile_hash.values(), test_hash.values(), train_hash.values()):
        filename = profile.filename.decode('utf-8')

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

# main control flow
if __name__ == "__main__":
    commands = ["start", "stop"]

    parser = argparse.ArgumentParser(description="Monitor system call sequences and detect anomalies.")
    #parser.add_argument("command", metavar="COMMAND", type=str.lower, choices=commands,
    #                    help="Command to run. Possible commands are %s." % ', '.join(commands))
    # TODO: implement this functionality (or perhaps remove it since it's only useful for testing)
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="write to a log file specified by <output>")
    args = parser.parse_args()

    # TODO: daemonize the process
    # TODO: use command to control daemonized process
    #command = args.command

    # check privileges
    if not ('SUDO_USER' in os.environ and os.geteuid() == 0):
        print("This script must be run with root privileges! Exiting.")
        exit()

    # create PROFILE_DIR if it does not exist
    if not os.path.exists(PROFILE_DIR):
        os.makedirs(PROFILE_DIR)

    # read BPF embedded C from bpf.c
    text = load_bpf("./bpf.c")

    # compile ebpf code
    bpf = BPF(text=text)
    # register callback to load profiles
    bpf.attach_uretprobe(name=LOADER_PATH, sym='load_profile', fn_name='pH_load_profile')
    execve_fnname = bpf.get_syscall_fnname("execve")
    bpf.attach_kprobe(event=execve_fnname, fn_name='pH_on_do_execve_file')

    # load in any profiles
    load_profiles()

    print("Tracing syscall sequences of length %s... Ctrl+C to quit." % SEQLEN)
    exiting = 0
    while True:
        # update the hashmap of sequences
        try:
            bpf.perf_buffer_poll()
            sleep(1)
        except KeyboardInterrupt: # handle exiting gracefully
            exiting = 1
            signal.signal(signal.SIGINT, signal_ignore)

        # exit control flow
        if exiting:
            # maybe redirect output
            if args.output is not None:
                sys.stdout = open(args.output,"w+")

            seq_hash = bpf["seq"]
            pro_hash = bpf["profile"]

            print_sequences()
            print_profiles()
            save_profiles()

            # clear the BPF hashmap
            seq_hash.clear()
            pro_hash.clear()

            # reset stdout
            if args.output is not None:
                sys.stdout.close()
                sys.stdout = sys.__stdout__

            print()
            print("Detaching...")
            exit()
