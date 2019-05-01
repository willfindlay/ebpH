#include <linux/sched.h>

#define SEQLEN         ARG_SEQLEN
#define PID            ARG_PID
#define USE_LAP        ARG_LAP
#define SYS_EXIT       60
#define SYS_EXIT_GROUP 231
#define SYS_EXECVE     59
#define SYS_FORK       57
#define EMPTY          9999

// a standard sequence
typedef struct
{
    u64 seq[SEQLEN];
    u64 count;
}
pH_seq;

// a lookahead pair
typedef struct
{
    u64 s1;
    u64 s2;
}
pH_lap;

// a pH profile consisting of sequences of lookahead pairs
typedef struct
{
    pH_lap seq[SEQLEN];
    u64 count;
}
pH_profile;

// function that returns the PPID of a process
static u32 ph_get_ppid()
{
    u32 ppid = -1;
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    ppid = (u32)task->real_parent->pid;

    return ppid;
}

// function that returns the PID of a process
static u32 ph_get_pid()
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    return (u32)pid_tgid;
}

// function that returns the process command
static char *ph_get_command()
{
    char *command = NULL;
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    command = (u32)task->comm;

    return command;
}

// function to be called when a fork systemcall is detected
// effectively deep copies the profile of the forking process to the child's profile
static void fork_lap_profile(pH_lap_profile* parent, pH_lap_profile* child)
{
    for(int i = 0; i < SEQLEN; i++)
    {
        child->seq[i] = parent->seq[i];
    }

    child->count = parent-> count;
}

// function to be called when an execve systemcall is detected
// effectively discards current profile for a process
static void execve_lap_profile(pH_lap_profile *pro)
{
    pro->count = 0;
}

BPF_HASH(seq, u64, pH_seq);
BPF_HASH(lap, u64, pH_lap_profile);

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    pH_seq lseq = {.count = 0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    long syscall = args->id;
    int i;

    // only trace one PID if specified
    if(PID != -1 && PID != (u32)pid_tgid)
        return 0;

    // initialize data
    for(int i = 0; i < SEQLEN; i++)
    {
        lseq.seq[i] = EMPTY;
    }

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

    // TODO: implement me
    // if we just forked, copy everything from the previous process to us
    if (syscall == SYS_FORK)
    {

    }

    if ((syscall == SYS_EXIT) || (syscall == SYS_EXIT_GROUP))
    {
      seq.delete(&pid_tgid);
    }
    else
    {
      seq.update(&pid_tgid, &lseq);
    }

    return 0;
}
