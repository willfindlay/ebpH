#include <linux/sched.h>

#define SEQLEN         ARG_SEQLEN
#define PID            ARG_PID
#define USE_LAP        ARG_LAP
#define SYS_EXIT       60
#define SYS_EXIT_GROUP 231
#define SYS_EXECVE     59
#define SYS_CLONE      56
#define SYS_FORK       57
#define SYS_VFORK       57
#define EMPTY          9999

// a standard sequence
typedef struct
{
    u64 seq[SEQLEN];
    u64 count;
    char comm[TASK_COMM_LEN];
}
pH_seq;

// TODO: add a structure for a lookahead pair

// TODO: add a structure for profiles

// function that returns the pid_tgid of a process' parent
static u64 pH_get_ppid_tgid()
{
    u64 ppid_tgid;
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    ppid_tgid = ((u64)task->real_parent->tgid << 32) | (u64)task->real_parent->pid;

    return ppid_tgid;
}

// TODO: convert this to a profile hashmap
BPF_HASH(seq, u64, pH_seq);

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
