#!/usr/bin/python

# ebpH --  monitor syscall sequences and detect anomalies
# Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca)
#
# based on Sasha Goldshtein's syscount
#  https://github.com/iovisor/bcc/blob/master/tools/syscount.py
#  Copyright 2017, Sasha Goldshtein.
# and on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2002 Anil Somayaji
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
from bcc import BPF
from bcc.utils import printb
from bcc.syscall import syscall_name, syscalls
import ctypes as ct
from pprint import pprint

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

parser = argparse.ArgumentParser(
    description="Per-process syscall counts.")
parser.add_argument("-p", "--pid", type=int, default=-1,
                    help="trace only this pid; supercedes --top option")
parser.add_argument("-t", "--top", type=int, default=10,
                    help="print only the top processes by syscall count or latency")
parser.add_argument("-s", "--seqlen", type=int, default=8,
                    help="print call sequences of max length <seqlen>")
parser.add_argument("-o", "--output", type=str, default=None,
                    help="write to a log file specified by <output>")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()

# hash for sequences per process
# hash for profiles per executable

with open("./bpf.c", "r") as f:
    text = f.read()

# sub in args
text = text.replace("ARG_SEQLEN", str(args.seqlen))
text = text.replace("ARG_PID", str(args.pid))

if args.ebpf:
    print(text)
    exit()

bpf = BPF(text=text)

def print_sequences():
    # fetch BPF hashmap
    seq_hash = bpf["seq"]

    # print system time
    print()
    print("[%s]" % strftime("%H:%M:%S %p"))

    # print sequence for each inspected process
    for p, s in seq_hash.items()[:args.top]:
        pid = p.value >> 32
        names = map(syscall_name, s.seq);
        calls = map(str, s.seq);

        # separator
        print()
        print("----------------------------------------------------------")
        print()

        # print the process and the sequence length
        print("%-8s %-8s" % ("PID","S-Length"))
        print("%-8s %-8s" % (pid, s.count));

        # list of sequences by "Call Name(Call Number),"
        print()
        print('Sequence:')
        s = ""
        for call,name in zip(calls,names):
            if call == "9999":
                break
            s+= "%s(%s), " % (name.decode('utf-8'), call);
        print(textwrap.fill(s))
        print()
    # clear the BPF hashmap
    seq_hash.clear()

if __name__ == "__main__":
    print("Tracing syscall sequences of length %d, for top %d processes... Ctrl+C to quit." % (args.seqlen, args.top))
    exiting = 0
    seconds = 0
    while True:
        # update the hashmap every 2 seconds
        try:
            sleep(2)
            seconds += 2
            seq_hash = bpf["seq"]
            l = len(seq_hash.items())
            print("%d processes" % l)
        # handle exiting gracefully
        except KeyboardInterrupt:
            exiting = 1
            signal.signal(signal.SIGINT, signal_ignore)

        # print the sequences before exiting
        if exiting:
            # maybe redirect output
            if args.output is not None:
                sys.stdout = open(args.output,"w+")

            print_sequences()

            # reset stdout
            if args.output is not None:
                sys.stdout.close()
                sys.stdout = sys.__stdout__

            print()
            print("Detaching...")
            exit()
