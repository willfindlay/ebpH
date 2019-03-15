#!/usr/bin/python

# process-syscount  count syscalls per process
# Copyright 2019 Anil Somayaji (soma@scs.carleton.ca)
#
# based on Sasha Goldshtein's syscount
#  https://github.com/iovisor/bcc/blob/master/tools/syscount.py
#  Copyright 2017, Sasha Goldshtein.
#
# USAGE: process-syscount.py
#
# Licensed under the Apache License, Version 2.0 (the "License")

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

text = """
#define SEQLEN ARG_SEQLEN
#define PID    ARG_PID
#define SYS_EXIT 60
#define SYS_EXIT_GROUP 231

typedef struct {
   u64 seq[SEQLEN];
   u64 count;
} pH_seq;

//typedef u64 pH_seq2[SEQLEN];

BPF_HASH(seq, u64, pH_seq);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    pH_seq lseq = {.count = 0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    long syscall = args->id;
    int i;

    // only trace one PID if specified
    if(PID != -1 && PID != (u32)pid_tgid)
        return 0;

    // initialize data
    for(int i = 0; i < SEQLEN; i++) {
        lseq.seq[i] = 9999;
    }

    //
    pH_seq *s;
    s = seq.lookup_or_init(&pid_tgid, &lseq);
    lseq = *s;

    lseq.count++;
    for (i = SEQLEN-1; i > 0; i--) {
       lseq.seq[i] = lseq.seq[i-1];
    }
    lseq.seq[0] = syscall;


    if ((syscall == SYS_EXIT) || (syscall == SYS_EXIT_GROUP)) {
      seq.delete(&pid_tgid);
    } else {
      seq.update(&pid_tgid, &lseq);
    }

    return 0;
}
"""

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
