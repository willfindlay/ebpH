/*
 * ebpH --  Monitor syscall sequences and detect anomalies
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
 * Licensed under MIT License */

// if we are running Linux 4.13 we need the two definitions below
//#define randomized_struct_fields_start  struct {
//#define randomized_struct_fields_end    };

#include <linux/sched.h>

// arguments
#define SEQLEN         ARG_SEQLEN
#define PID            ARG_PID
#define USE_LAP        ARG_LAP

// table size to use for hashmaps
// set to BPF default for now
#define TABLE_SIZE 10240

// pH_task definitions
#define PH_LOCALITY_WIN 128

// pH_profile definitions
#define PH_NUM_SYSCALLS 512

// important syscall definitions
#define SYS_EXIT       60
#define SYS_EXIT_GROUP 231
#define SYS_EXECVE     59
#define SYS_CLONE      56
#define SYS_FORK       57
#define SYS_VFORK      58
#define EMPTY          9999

// *** pH task data structures ***

typedef struct pH_profile pH_profile;

// a locality
// TODO: implement me
typedef struct
{
    unsigned char win[PH_LOCALITY_WIN];
    int first, lfc, max_lfc;
}
pH_locality;

// a standard sequence
typedef struct
{
    pH_locality lf;
    u64 seq[SEQLEN];
    u64 count;
    int delay;
    char comm[TASK_COMM_LEN];
}
pH_seq;

// *** pH profile data structures ***

// profile data
// TODO: implement me
typedef struct
{
    u64 last_mod_count;
    u64 train_count;
    unsigned char entry[PH_NUM_SYSCALLS][PH_NUM_SYSCALLS];
}
pH_profile_data;

// per executable profile
// TODO: implement me
struct pH_profile
{
    int normal;
    int frozen;
    time_t normal_time;
    u64 window_size;
    u64 count;
    u64 anomalies;
    char comm[TASK_COMM_LEN];
};

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

// sequences hashed by pid_tgid
BPF_HASH(seq, u64, pH_seq);
BPF_HASH(pro, u64, pH_profile); // hashed by a function of comm string -- see pH_hash_comm_str(char *comm)
BPF_HASH(seq_to_pro, pH_seq *, pH_profile);
BPF_HASH(pro_to_test_data,  pH_profile *, pH_profile_data);
BPF_HASH(pro_to_train_data, pH_profile *, pH_profile_data);

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    pH_seq lseq = {.count = 0};
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
    }

    if ((syscall == SYS_EXIT) || (syscall == SYS_EXIT_GROUP))
    {
        // FIXME: had to comment this out for testing purposes
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
        for(int i = 0; i < SEQLEN; i++)
        {
            lseq.seq[i] = parent_seq->seq[i];
        }

        // init child sequence
        seq.lookup_or_init(&pid_tgid, &lseq);
    }

    return 0;
}
