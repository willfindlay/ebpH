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
# Licensed under MIT License

from time import sleep, strftime
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

# signal handler
def signal_ignore(signal, frame):
    print()

commands = ["start", "stop"]

parser = argparse.ArgumentParser(description="Monitor system call sequences and detect anomalies.")
parser.add_argument("command", metavar="COMMAND", type=str.lower, choices=commands,
                    help=f"Command to run. Possible commands are {', '.join(commands)}.")
args = parser.parse_args()

# check command
command = args.command

with open("./bpf.c", "r") as f:
    text = f.read()

# sub in args
# since I removed the args for now, these are hardcoded as 8 and -1 respectively
args.seqlen = 8
args.pid = -1
text = text.replace("ARG_SEQLEN", str(args.seqlen))
text = text.replace("ARG_PID", str(args.pid))

# compile ebpf code
bpf = BPF(text=text)

# main control flow
if __name__ == "__main__":
    print(f"Tracing syscall sequences of length {args.seqlen}... Ctrl+C to quit.")
    exiting = 0
    seconds = 0
    while True:
        # update the hashmap of sequences
        try:
            # sleep(2)
            # seconds += 2
            seq_hash = bpf["seq"]
            sleep(1)
        except KeyboardInterrupt: # handle exiting gracefully
            exiting = 1
            signal.signal(signal.SIGINT, signal_ignore)

        # exit control flow
        if exiting:
            print()
            print("Detaching...")
            exit()
