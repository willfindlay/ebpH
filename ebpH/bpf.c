/* ebpH --  Monitor syscall sequences and detect anomalies
 * Copyright 2019 Anil Somayaji (soma@scs.carleton.ca) and
 * William Findlay (williamfindlay@cmail.carleton.ca)
 *
 * Based on Sasha Goldshtein's syscount
 *  https://github.com/iovisor/bcc/blob/master/tools/syscount.py
 *  Copyright 2017, Sasha Goldshtein.
 * And on Anil Somayaji's pH
 *  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
 *  Copyright 2003 Anil Somayaji
 *
 * USAGE: ebpH.py <COMMAND>
 *
 * Licensed under GPL v3 License */

#include <linux/sched.h>
#include "defs.h"
#include "profiles.h"

// *** helper functions ***

// initialize a pH profile
static void pH_init_profile(pH_profile *p)
{
    p->normal = 0;
    p->frozen = 0;
    p->normal_time = 0;
    p->window_size = 0;
    p->count = 0;
    p->anomalies = 0;
    bpf_get_current_comm(&p->comm, sizeof(p->comm));
}

// reset a locality for a task
static inline void pH_reset_locality(pH_seq *s)
{
    for(int i = 0; i < PH_LOCALITY_WIN; i++)
    {
        s->lf.win[i] = 0;
    }

    s->lf.total = 0;
    s->lf.max = 0;
    s->lf.first = PH_LOCALITY_WIN - 1;
}

// intialize a pH sequence
static void pH_init_sequence(pH_seq *s)
{
    pH_reset_locality(s);
}

// function that returns the pid_tgid of a process' parent
static u64 pH_get_ppid_tgid()
{
    u64 ppid_tgid;
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    ppid_tgid = ((u64)task->real_parent->tgid << 32) | (u64)task->real_parent->pid;

    return ppid_tgid;
}

// function to hash a comm string
// this is necessary for the pro BPF_HASH
static u64 pH_hash_comm_str(char *comm)
{
    u64 hash = 0;

    for(int i = 0; i < TASK_COMM_LEN; i++)
    {
        hash = 37 * hash + (u64) comm[i];
    }

    hash %= TABLE_SIZE;

    return hash;
}

// *** BPF hashmaps ***

// sequences hashed by pid_tgid
BPF_HASH(seq, u64, pH_seq);

// profiles hashed by a function of comm string -- see pH_hash_comm_str(char *comm)
BPF_HASH(pro, u64, pH_profile);

// profiles hashed by sequences
BPF_HASH(seq_to_pro, pH_seq *, pH_profile *);

// test data hashed by profiles
BPF_HASH(pro_to_test_data,  pH_profile *, pH_profile_data);

// training data hashed by profiles
BPF_HASH(pro_to_train_data, pH_profile *, pH_profile_data);

// *** BPF tracepoints ***

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    pH_seq lseq = {.count = 0};
    //u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    long syscall = args->id;
    int i;

    // initialize data
    for(int i = 0; i < SEQLEN; i++)
    {
        lseq.seq[i] = EMPTY;
    }

    bpf_get_current_comm(&lseq.comm, sizeof(lseq.comm));

    pH_seq *s;
    s = seq.lookup_or_init(&pid_tgid, &lseq);
    lseq = *s;

    lseq.count++;
    for (i = SEQLEN-1; i > 0; i--)
    {
       lseq.seq[i] = lseq.seq[i-1];
    }
    lseq.seq[0] = syscall;

    // if we just EXECVE'd, we need to wipe the sequence
    if(syscall == SYS_EXECVE)
    {
        // leave the EXECVE call, wipe the rest
        for(int i = 1; i < SEQLEN; i++)
        {
            lseq.seq[i] = EMPTY;
        }
        lseq.count = 1;

        // and set comm
        bpf_probe_read(&lseq.comm, sizeof(lseq.comm), ((char *)args->args[0]));
    }

    if ((syscall == SYS_EXIT) || (syscall == SYS_EXIT_GROUP))
    {
        //seq.delete(&pid_tgid);
    }
    else
    {
        seq.update(&pid_tgid, &lseq);
    }

    return 0;
}

// we need the return value from fork syscalls in order to copy profiles over
TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    pH_seq lseq = {.count = 0};
    pH_seq *parent_seq;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    long syscall = args->id;

    // if we are forking, we need to copy our profile to the next
    if(syscall == SYS_FORK || syscall == SYS_CLONE || syscall == SYS_VFORK)
    {
        // get return value of function
        u64 retval = (u64)args->ret;

        // we want to be inside the child process
        if(retval != 0)
            return 0;

        // get parent PID
        u64 ppid_tgid = pH_get_ppid_tgid();

        // fetch parent sequence
        parent_seq = seq.lookup(&ppid_tgid);
        if(parent_seq == NULL)
            return 0;

        // copy data to child sequence
        lseq.count = parent_seq->count;
        bpf_probe_read(&lseq.comm, sizeof(lseq.comm), &parent_seq->comm);
        for(int i = 0; i < SEQLEN; i++)
        {
            lseq.seq[i] = parent_seq->seq[i];
        }

        // init child sequence
        seq.lookup_or_init(&pid_tgid, &lseq);
    }

    return 0;
}

// load a profile
int load_profile(struct pt_regs *ctx)
{
    // TODO: make this work for profiles instead of sequences
    //       below is just test code
    pH_seq s;

    // read return of profile load function from userspace
    bpf_probe_read(&s, sizeof(s), (void *)PT_REGS_RC(ctx));

    // a sentinel PID for test purposes
    u64 x = (u64)1337 << 32;
    seq.lookup_or_init(&x, &s);

    return 0;
}
