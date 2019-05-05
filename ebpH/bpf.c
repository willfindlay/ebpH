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

#define BPF_LICENSE GPL

// *** BPF hashmaps ***

// sequences hashed by pid_tgid
BPF_HASH(seq, u64, pH_seq);

// profiles
BPF_HASH(profile, u64, pH_profile);

// profiles hashed by sequences
BPF_HASH(seq_to_pro, pH_seq *, pH_profile *);

// test data hashed by profiles
BPF_HASH(pro_to_test_data,  pH_profile *, pH_profile_data);

// training data hashed by profiles
BPF_HASH(pro_to_train_data, pH_profile *, pH_profile_data);

// *** helper functions ***

// reset a locality for a task
static void pH_reset_locality(pH_seq *s)
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

// function to hash a string
// this is necessary for the profiles hashmap
static u64 pH_hash_str(char *s)
{
    u64 hash = 0;

    for(int i = 0; i < TASK_COMM_LEN; i++)
    {
        hash = 37 * hash + (u64) s[i];
    }

    hash %= TABLE_SIZE;

    return hash;
}

// *** pH sequence create/update subroutines ***

// TODO: this could be a little more performant if we optimize for sequences
//       that don't need to be initialized
static int pH_create_or_update_sequence(long *syscall, u64 *pid_tgid)
{
    int i;
    pH_seq s = {.count = 0};

    if(syscall == NULL || pid_tgid == NULL)
        return -1;

    // intialize sequence data
    for(i = 0; i < SEQLEN; i++)
    {
        s.seq[i] = EMPTY;
    }

    // either init this pid's sequence or copy it from the map
    // if it already exists
    pH_seq *temp;
    temp = seq.lookup_or_init(pid_tgid, &s);
    s = *temp;

    // if we just execve'd we need to wipe the sequence
    if(*syscall == SYS_EXECVE)
    {
        // leave the EXECVE call, wipe the rest
        for(i = 1; i < SEQLEN; i++)
        {
            s.seq[i] = EMPTY;
        }
        s.count = 1;
    }
    // otherwise we simply shift everything over
    else
    {
        // add the system call to the sequence of calls
        s.count++;
        for(i = SEQLEN - 1; i > 0; i--)
        {
            s.seq[i] = s.seq[i-1];
        }
    }

    // insert the syscall at the beginning of the sequence
    s.seq[0] = *syscall;

    if ((*syscall == SYS_EXIT) || (*syscall == SYS_EXIT_GROUP))
    {
        // FIXME: this is commented out for test purposes
        //seq.delete(pid_tgid);
    }
    else
    {
        seq.update(pid_tgid, &s);
    }

    return 0;
}

// called when pH detects a fork system call
// we use this to copy the parent's sequence to the child
static int pH_copy_sequence_on_fork(u64 *pid_tgid, u64 *ppid_tgid, u64 *execve_ret)
{
    // child sequence
    pH_seq s = {.count = 0};
    // parent sequence
    pH_seq *parent_seq;

    if(pid_tgid == NULL || ppid_tgid == NULL)
        return -1;

    // we want to be inside the child process
    if(*execve_ret != 0)
        return 0;

    // fetch parent sequence
    parent_seq = seq.lookup(ppid_tgid);
    if(parent_seq == NULL)
        return 0;

    // copy data to child sequence
    s.count = parent_seq->count;
    for(int i = 0; i < SEQLEN; i++)
    {
        s.seq[i] = parent_seq->seq[i];
    }

    // init child sequence
    seq.lookup_or_init(pid_tgid, &s);

    return 0;
}

// *** pH profile create/update subroutines ***

// create or update a pH profile
// TODO: finish this (right now it just creates a sequence with nothing in it)
//       also -- need to create two sets of profile data and link it with separate hashmaps
static int pH_create_or_update_profile(char *filename, u64 *pid_tgid, long *syscall)
{
    int i;
    u64 hash;
    pH_profile p = {.normal = 0, .frozen = 0, .normal_time = 0,
                    .window_size = 0, .count = 0, .anomalies = 0};
    pH_profile *temp;

    if(filename == NULL || pid_tgid == NULL || syscall == NULL)
        return -1;

    if(*syscall == SYS_EXECVE)
    {
        // initialize the filename
        bpf_probe_read_str(&p.filename, sizeof(p.filename), filename);

        // hash the filename
        hash = pH_hash_str(p.filename);
        // either init the profile or copy it from the map if it exists
        temp = profile.lookup_or_init(&hash, &p);
    }

    return 0;
}

// *** BPF tracepoints ***

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    long syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // create or update the sequence for this pid_tgid
    pH_create_or_update_sequence(&args->id, &pid_tgid);

    // create or update the profile for this executable
    pH_create_or_update_profile((char *) args->args[0], &pid_tgid, &syscall);

    return 0;
}

// we need the return value from fork syscalls in order to copy profiles over
TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    long syscall = args->id;
    // get PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // get parent's PID
    u64 ppid_tgid = pH_get_ppid_tgid();

    // if we are forking, we need to copy our profile to the next
    if(syscall == SYS_FORK || syscall == SYS_CLONE || syscall == SYS_VFORK)
    {
        pH_copy_sequence_on_fork(&pid_tgid, &ppid_tgid, (u64 *) &args->ret);
    }

    return 0;
}

// load a profile
int pH_load_profile(struct pt_regs *ctx)
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
