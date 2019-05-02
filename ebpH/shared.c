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
    int first;
    int total;
    int max;
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

// *** shared functions ***

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
