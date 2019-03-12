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
parser.add_argument("-p", "--pid", type=int, help="trace only this pid")
parser.add_argument("-t", "--top", type=int, default=10,
                    help="print only the top syscalls by count or latency")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()

# hash for sequences per process
# hash for profiles per executable

SEQLEN = 20

text = """
#define SEQLEN %d
#define SYS_EXIT 60
#define SYS_EXIT_GROUP 231

typedef struct {
   u64 seq[SEQLEN];
   u64 count;
} pH_seq;

typedef u64 pH_seq2[SEQLEN];

BPF_HASH(seq, u64, pH_seq);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    pH_seq lseq = {.count = 0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    long syscall = args->id;
    int i;

    for(int i = 0; i < SEQLEN; i++) {
        lseq.seq[i] = 9999;
    }

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
""" % (SEQLEN)

if args.ebpf:
    print(text)
    exit()

bpf = BPF(text=text)

def print_sequences():
    seq_hash = bpf["seq"]
    print("[%s]" % strftime("%H:%M:%S"))
    #print("%-22s %-8s" % ("Process", "Sequence"))
    for p, s in seq_hash.items()[:args.top]:
        pid = p.value >> 32
        names = map(syscall_name, s.seq);
        calls = map(str, s.seq);

        print()
        print("----------------------------------------------------------")
        print()

        print("%-12s %-15s" % ("Process","Sequence Length"))
        print("%-12s %-15s" % (pid, s.count));

        print('Sequence {Call(Number)}:')
        for call,name in zip(calls,names):
            if call == "9999":
                break
            print("%s(%s), " % (name.decode('utf-8'), call), end="");
        print()
    seq_hash.clear()

print("Tracing syscall sequences, printing %d... Ctrl+C to quit." % (args.top))
exiting = 0
seconds = 0
while True:
    try:
        sleep(2)
        seconds += 2
        seq_hash = bpf["seq"]
        l = len(seq_hash.items())
        print("%d processes" % l)
    except KeyboardInterrupt:
        exiting = 1
        signal.signal(signal.SIGINT, signal_ignore)

    if exiting:
        print_sequences()
        print("Detaching...")
        exit()
