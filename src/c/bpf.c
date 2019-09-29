/* ebpH --  An eBPF intrusion detection program.
 * -------  Monitors system call patterns and detect anomalies.
 * Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
 * Anil Somayaji (soma@scs.carleton.ca)
 *
 * Based on Anil Somayaji's pH
 *  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
 *  Copyright 2003 Anil Somayaji
 *
 * USAGE: ebphd <COMMAND>
 *
 * Licensed under GPL v2 License */

#include <linux/sched.h>
#include <linux/fdtable.h>
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/timekeeping.h>

#include "src/c/defs.h"
#include "src/c/ebph.h"

#define EBPH_ERROR(MSG, CTX) char m[] = (MSG); __ebpH_log_error(m, sizeof(m), (CTX))
#define EBPH_WARNING(MSG, CTX) char m[] = (MSG); __ebpH_log_warning(m, sizeof(m), (CTX))
#define EBPH_DEBUG(MSG, CTX) char m[] = (MSG); __ebpH_log_debug(m, sizeof(m), (CTX))
#define EBPH_INFO(MSG, CTX) char m[] = (MSG); __ebpH_log_info(m, sizeof(m), (CTX))

BPF_PERF_OUTPUT(ebpH_error);
BPF_PERF_OUTPUT(ebpH_warning);
BPF_PERF_OUTPUT(ebpH_debug);
BPF_PERF_OUTPUT(ebpH_info);

/* log an error -- this function should not be called, use macro EBPH_ERROR instead */
static inline void __ebpH_log_error(char *m, int size, struct pt_regs *ctx)
{
    ebpH_error.perf_submit(ctx, m, size);
}

/* log a warning -- this function should not be called, use macro EBPH_WARNING instead */
static inline void __ebpH_log_warning(char *m, int size, struct pt_regs *ctx)
{
    ebpH_warning.perf_submit(ctx, m, size);
}

/* log a debug message -- this function should not be called, use macro EBPH_DEBUG instead */
static inline void __ebpH_log_debug(char *m, int size, struct pt_regs *ctx)
{
    ebpH_debug.perf_submit(ctx, m, size);
}

/* log a info message -- this function should not be called, use macro EBPH_INFO instead */
static inline void __ebpH_log_info(char *m, int size, struct pt_regs *ctx)
{
    ebpH_info.perf_submit(ctx, m, size);
}

/* BPF tables below this line --------------------- */

/* pid_tgid to ebpH_process */
BPF_HASH(processes, u64, struct ebpH_process, EBPH_PID_TGID_SIZE);

/* inode key to ebpH_profile */
BPF_HASH(profiles, u64, struct ebpH_profile);

/* WARNING: NEVER ACCESS THIS DIRECTLY!! */
BPF_ARRAY(__executable_init, struct ebpH_profile, 1);
BPF_ARRAY(__process_init, struct ebpH_process, 1);

/* Main syscall event buffer */
BPF_PERF_OUTPUT(on_executable_processed);
BPF_PERF_OUTPUT(on_pid_assoc);
BPF_PERF_OUTPUT(on_anomaly);

/* Function definitions below this line --------------------- */

static long ebpH_get_lookahead_index(u64 *curr, u64* prev, struct pt_regs *ctx)
{
    if (!curr)
    {
        EBPH_ERROR("NULL curr syscall -- ebpH_update_lookahead", ctx);
        return -1;
    }

    if (!prev)
    {
        EBPH_ERROR("NULL prev syscall -- ebpH_update_lookahead", ctx);
        return -1;
    }

    if (*curr >= EBPH_NUM_SYSCALLS)
    {
        EBPH_ERROR("Access out of bounds (curr)... Please update maximum syscall number -- ebpH_update_lookahead", ctx);
        return -1;
    }

    if (*prev >= EBPH_NUM_SYSCALLS)
    {
        EBPH_ERROR("Access out of bounds (prev)... Please update maximum syscall number -- ebpH_update_lookahead", ctx);
        return -1;
    }

    return (long) (*curr * EBPH_NUM_SYSCALLS + *prev);
}

static int ebpH_process_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    int anomalies = 0;

    if (profile->normal)
    {
        anomalies = ebpH_test(profile, process, ctx);
        if (anomalies)
        {
            struct ebpH_anomaly event = {.pid=(process->pid_tgid >> 32), .key=profile->key, .syscall=process->seq[0],
                .anomalies=anomalies};
            bpf_probe_read_str(event.comm, sizeof(event.comm), profile->comm);
            on_anomaly.perf_submit(ctx, &event, sizeof(event));

            if (profile->anomalies > EBPH_ANOMALY_LIMIT)
            {
                ebpH_stop_normal(profile, process, ctx);
            }
        }
    }

    profile->anomalies += anomalies;

    return 0;
}

static int ebpH_test(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    int mismatches = 0;
    long entry = -1;

    if (!process || process->count < 1)
        return mismatches;

    /* access at index [syscall][prev] */
    for (int i = 1; i < EBPH_SEQLEN; i++)
    {
        u64 syscall = process->seq[0];
        u64 prev = process->seq[i];
        if (prev == EBPH_EMPTY)
            break;

        /* determine which entry we need */
        entry = ebpH_get_lookahead_index(&syscall, &prev, ctx);

        /* lookup the syscall data */
        u8 data = profile->flags[entry];

        /* check for mismatch */
        if ((data & (1 << (i-1))) == 0)
        {
            mismatches++;
        }
    }

    return mismatches;
}

static int ebpH_train(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    /* update train_count and last_mod_count */
    profile->train_count++;
    if (ebpH_test(profile, process, ctx))
    {
        if (profile->frozen)
            profile->frozen = 0;
        ebpH_seq_to_lookahead(profile, process, ctx);
        profile->last_mod_count = 0;
    }
    else
    {
        profile->last_mod_count++;

        if (profile->frozen)
            return 0;

        profile->normal_count = profile->train_count - profile->last_mod_count;

        if ((profile->normal_count > 0) && (profile->train_count * EBPH_NORMAL_FACTOR_DEN >
                    profile->normal_count * EBPH_NORMAL_FACTOR))
        {
            profile->frozen = 1;
            ebpH_set_normal_time(profile, ctx);
        }
    }

    return 0;
}

static int ebpH_start_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    profile->normal = 1;
    profile->frozen = 0;
    profile->anomalies = 0;
    profile->last_mod_count = 0;

    ebpH_reset_ALF(process, ctx);

    return 0;
}

static int ebpH_stop_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    profile->normal = 0;
    ebpH_reset_ALF(process, ctx);

    return 0;
}

static int ebpH_set_normal_time(struct ebpH_profile *profile, struct pt_regs *ctx)
{
    u64 time_ns = (u64) bpf_ktime_get_ns();
    time_ns += EBPH_NORMAL_WAIT;

    profile->normal_time = time_ns;

    return 0;
}

static int ebpH_check_normal_time(struct ebpH_profile *profile, struct pt_regs *ctx)
{
    u64 time_ns = (u64) bpf_ktime_get_ns();
    if (profile->frozen && (time_ns > profile->normal_time))
        return 1;

    return 0;
}

static int ebpH_reset_ALF(struct ebpH_process *process, struct pt_regs *ctx)
{
    for (int i=0; i < EBPH_LOCALITY_WIN; i++)
    {
        process->lf.win[i] = 0;
    }

    process->lf.lfc = 0;
    process->lf.lfc_max = 0;

    return 0;
}

static int ebpH_seq_to_lookahead(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    int mismatches = 0;
    long entry = -1;

    if (!process || process->count < 1)
        return mismatches;

    /* access at index [syscall][prev] */
    for (int i = 1; i < EBPH_SEQLEN; i++)
    {
        u64 syscall = process->seq[0];
        u64 prev = process->seq[i];
        if (prev == EBPH_EMPTY)
            break;

        /* determine which entry we need */
        entry = ebpH_get_lookahead_index(&syscall, &prev, ctx);

        /* lookup the syscall data */
        u8 data = profile->flags[entry];

        /* set lookahead pair */
        data |= (1 << (i - 1));
        profile->flags[entry] = data;
    }

    return 0;
}

static int ebpH_process_syscall(struct ebpH_process *process, u64* syscall, struct pt_regs *ctx)
{
    struct ebpH_profile *profile;

    if (!process)
    {
        EBPH_ERROR("NULL process -- ebpH_process_syscall", ctx);
        return -1;
    }

    if (!syscall)
    {
        EBPH_ERROR("NULL syscall -- ebpH_process_syscall", ctx);
        return -1;
    }

    profile = profiles.lookup(&(process->exe_key));

    if (!profile)
    {
        EBPH_ERROR("NULL profile -- ebpH_process_syscall", ctx);
        return -1;
    }

    /* Add syscall to process sequence */
    for (int i = 1; i < EBPH_SEQLEN; i++)
    {
        process->seq[i] = process->seq[i-1];
    }
    process->seq[0] = *syscall;
    process->count = process->count < EBPH_SEQLEN ? process->count + 1 : process->count;

    ebpH_process_normal(profile, process, ctx);

    ebpH_train(profile, process, ctx);

    /* Update normal status if we are frozen and have reached normal_time */
    if (ebpH_check_normal_time(profile, ctx))
    {
        ebpH_start_normal(profile, process, ctx);
    }

    profiles.update(&(profile->key), profile);
    return 0;
}

/* Return the parent process id of the task making the current systemcall.
 * This is useful for when we need to copy the parent process' profile during a fork. */
static u64 ebpH_get_ppid_tgid()
{
    u64 ppid_tgid;
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    ppid_tgid = ((u64)task->real_parent->tgid << 32) | (u64)task->real_parent->pid;

    return ppid_tgid;
}

/* Create process struct, associate it with the correct PID and the correct profile */
static int ebpH_start_tracing(struct ebpH_profile *e, u64 *pid_tgid, struct pt_regs *ctx)
{
    int zero = 0;
    struct ebpH_process *init;

    if (!e)
    {
        EBPH_ERROR("NULL profile -- ebpH_associate_pid_exe", ctx);
        return -1;
    }

    if (!pid_tgid)
    {
        EBPH_ERROR("NULL pid_tgid -- ebpH_associate_pid_exe", ctx);
        return -1;
    }

    /* get the address of the zeroed executable struct */
    init = __process_init.lookup(&zero);

    if (!init)
    {
        EBPH_ERROR("NULL init -- ebpH_process_executable", ctx);
        return -1;
    }

    /* copy memory over */
    bpf_probe_read(init, sizeof(struct ebpH_process), init);
    init->exe_key = e->key;
    init->pid_tgid = *pid_tgid;

    for (int i = 0; i < EBPH_SEQLEN; i++)
        init->seq[i] = EBPH_EMPTY;

    processes.update(pid_tgid, init);

    struct ebpH_information info = {.pid=(u32)((*pid_tgid) >> 32), .key=e->key};
    bpf_probe_read_str(info.comm, sizeof(info.comm), e->comm);
    on_pid_assoc.perf_submit(ctx, &info, sizeof(info));

    return 0;
}

/* Register information about an executable if necessary
 * and associate PIDs with profiles.
 * This is invoked every time the kernel calls on_do_open_execat. */
static int ebpH_on_profile_exec(u64 *key, u64 *pid_tgid, struct pt_regs *ctx, char *comm)
{
    int zero = 0;
    struct ebpH_profile *init = NULL;
    struct ebpH_profile *ep = NULL;

    if (!key)
    {
        EBPH_ERROR("NULL key -- ebpH_process_executable", ctx);
        return -1;
    }

    if (!comm)
    {
        EBPH_ERROR("NULL comm -- ebpH_process_executable", ctx);
        return -1;
    }

    if (!pid_tgid)
    {
        EBPH_ERROR("NULL pid_tgid -- ebpH_process_executable", ctx);
        return -1;
    }

    // FIXME: this should prevent shared libraries from overwriting real binaries but...
    //        it's also stopping some legit overwrites... commented for now
    //if (processes.lookup(pid_tgid))
    //{
    //    return 0;
    //}

    /* Get the address of the zeroed executable struct */
    init = __executable_init.lookup(&zero);

    if (!init)
    {
        EBPH_ERROR("NULL init -- ebpH_process_executable", ctx);
        return -1;
    }

    /* Copy memory over */
    bpf_probe_read(init, sizeof(struct ebpH_profile), init);

    ep = profiles.lookup(key);
    if (ep)
    {
        goto start_tracing;
    }

    ep = init;
    ep->key = *key;
    bpf_probe_read_str(ep->comm, sizeof(ep->comm), comm);

    profiles.update(key, ep);

    struct ebpH_information info = {.pid=(u32)((*pid_tgid) >> 32), .key=ep->key};
    bpf_probe_read_str(info.comm, sizeof(info.comm), ep->comm);
    on_executable_processed.perf_submit(ctx, &info, sizeof(info));

start_tracing:
    ebpH_start_tracing(ep, pid_tgid, ctx);

    return 0;
}

/* Tracepoints and kprobes below this line --------------------- */

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u64 syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ebpH_process *process;

    process = processes.lookup(&pid_tgid);

    /* Not tracing this process */
    if (!process)
    {
        return 0;
    }

    /* The juicy stuff goes right here */
    ebpH_process_syscall(process, &syscall, (struct pt_regs *)args);

    /* Some extra logic for special syscalls */
    if (syscall == EBPH_EXIT || syscall == EBPH_EXIT_GROUP)
    {
        /* Disassociate the PID if the process has exited */
        processes.delete(&pid_tgid);
    }

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u64 syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ppid_tgid = ebpH_get_ppid_tgid();
    u64 key = 0;
    struct ebpH_profile *e;
    struct ebpH_process *process;

    /* Associate pids on fork */
    if (syscall == EBPH_FORK || syscall == EBPH_VFORK || syscall == EBPH_CLONE)
    {
       process = processes.lookup(&ppid_tgid);

       if (!process)
       {
           /* FIXME: This message is annoying. It will be more relevant when we are actually
            * starting the daemon on system startup. For now, we can comment it out. */
           //EBPH_WARNING("No data to copy to child process.", (struct pt_regs *)args);
           return 0;
       }

       key = process->exe_key;

       e = profiles.lookup(&key);

       if (!e)
       {
           /* We should never ever get here! */
           EBPH_ERROR("A key has become detached from its binary!", (struct pt_regs *)args);
           return -1;
       }

       ebpH_start_tracing(e, &pid_tgid, (struct pt_regs *)args);
    }

    return 0;
}

/* This is a special hook for execve-family calls
 * We need to inspect do_open_execat to snag information about the file
 * If this breaks in a future version of Linux (definitely possible!), I will be sad :( */
int ebpH_on_do_open_execat(struct pt_regs *ctx)
{
    struct file *exec_file;
    struct dentry *exec_entry;
    struct inode *exec_inode;
    u64 key = 0;
    char comm[EBPH_FILENAME_LEN];

    /* Yoink the file struct */
    exec_file = (struct file *)PT_REGS_RC(ctx);
    if (!exec_file || IS_ERR(exec_file))
    {
        /* If the file doesn't exist (invalid execve call), just return here */
        return -1;
    }

    /* Fetch dentry for executable */
    exec_entry = exec_file->f_path.dentry;
    if (!exec_entry)
    {
        EBPH_ERROR("Couldn't fetch the dentry for this executable -- ebpH_on_do_open_execat", ctx);
        return -1;
    }

    /* Fetch inode for executable */
    exec_inode = exec_entry->d_inode;
    if (!exec_inode)
    {
        EBPH_ERROR("Couldn't fetch the inode for this executable -- ebpH_on_do_open_execat", ctx);
        return -1;
    }

    /* We want a key to be comprised of device number in the upper 32 bits
     * and inode number in the lower 32 bits */
    key  = exec_inode->i_ino;
    key |= ((u64)exec_inode->i_rdev << 32);

    u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Load executable name into comm */
    struct qstr dn = {};
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&dn, sizeof(dn), &exec_entry->d_name);
    bpf_probe_read(&comm, sizeof(comm), dn.name);

    /* Store information about this executable */
    ebpH_on_profile_exec(&key, &pid_tgid, ctx, comm);

    return 0;
}
