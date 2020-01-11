/* ebpH     An eBPF intrusion detection program.
 *          Monitors system call patterns and detect anomalies.
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

#include "bpf/defs.h"
#include "bpf/bpf_program.h"

#define EBPH_ERROR(MSG, CTX) char m[] = (MSG); __ebpH_log_error(m, sizeof(m), (CTX))
#define EBPH_WARNING(MSG, CTX) char m[] = (MSG); __ebpH_log_warning(m, sizeof(m), (CTX))

/* TODO: deprecate some of these */
BPF_PERF_OUTPUT(ebpH_error);
BPF_PERF_OUTPUT(ebpH_warning);
BPF_PERF_OUTPUT(ebpH_debug_int);

/* Main syscall event buffer */
BPF_PERF_OUTPUT(on_executable_processed);
BPF_PERF_OUTPUT(on_pid_assoc);
BPF_PERF_OUTPUT(on_anomaly);

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

/* BPF tables below this line --------------------- */

/* pid_tgid to ebpH_process */
//BPF_HASH(processes, u32, struct ebpH_process, EBPH_PROCESSES_TABLE_SIZE);
BPF_F_TABLE("hash", u64, struct ebpH_process, processes, EBPH_PROCESSES_TABLE_SIZE, BPF_F_NO_PREALLOC);

/* inode key to ebpH_profile */
//BPF_HASH(profiles, u64, struct ebpH_profile, EBPH_PROFILES_TABLE_SIZE);
BPF_F_TABLE("hash", u64, struct ebpH_profile, profiles, EBPH_PROFILES_TABLE_SIZE, BPF_F_NO_PREALLOC);

/* Statistics */
BPF_HISTOGRAM(stats);

/* WARNING: These maps are READ-ONLY */
BPF_ARRAY(__profile_init, struct ebpH_profile, 1);
BPF_ARRAY(__process_init, struct ebpH_process, 1);

/* Store program state */
BPF_ARRAY(__is_saving, int, 1);
BPF_ARRAY(__is_monitoring, int, 1);

/* Function definitions below this line --------------------- */

static void stats_increment(int key)
{
    u64 *leaf = stats.lookup(&key);
    if (leaf) (void)__sync_fetch_and_add(leaf, 1);
}

static void stats_decrement(int key)
{
    u64 *leaf = stats.lookup(&key);
    if (leaf) (void)__sync_fetch_and_sub(leaf, 1);
}

static long ebpH_get_lookahead_index(long *curr, long* prev, struct pt_regs *ctx)
{
    if (!curr)
    {
        EBPH_ERROR("NULL curr syscall -- ebpH_get_lookahead_index", ctx);
        return 0;
    }

    if (!prev)
    {
        EBPH_ERROR("NULL prev syscall -- ebpH_get_lookahead_index", ctx);
        return 0;
    }

    if (*curr >= EBPH_NUM_SYSCALLS || *curr < 0)
    {
        EBPH_ERROR("Access out of bounds (curr)... Please update maximum syscall number -- ebpH_get_lookahead_index", ctx);
        return 0;
    }

    if (*prev >= EBPH_NUM_SYSCALLS || *prev < 0)
    {
        EBPH_ERROR("Access out of bounds (prev)... Please update maximum syscall number -- ebpH_get_lookahead_index", ctx);
        return 0;
    }

    return (long) (*curr * EBPH_NUM_SYSCALLS + *prev);
}

static int ebpH_process_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    int anomalies = 0;

    if (profile->normal)
    {
        anomalies = ebpH_test(&(profile->test), process, ctx);
        if (anomalies)
        {
            struct ebpH_anomaly event = {.pid=process->pid, .key=profile->key, .syscall=process->seq[0],
                .anomalies=anomalies};
            bpf_probe_read_str(event.comm, sizeof(event.comm), profile->comm);
            on_anomaly.perf_submit(ctx, &event, sizeof(event));

            if (profile->anomalies > EBPH_ANOMALY_LIMIT)
            {
                ebpH_stop_normal(profile, process, ctx);
            }
        }
    }

    ebpH_add_anomaly_count(profile, process, anomalies, ctx);

    return 0;
}

static int ebpH_test(struct ebpH_profile_data *data, struct ebpH_process *process, struct pt_regs *ctx)
{
    int mismatches = 0;
    long entry = -1;

    if (!process || process->count < 1)
        return mismatches;

    /* access at index [syscall][prev] */
    for (int i = 1; i < EBPH_SEQLEN; i++)
    {
        long syscall = process->seq[0];
        long prev = process->seq[i];
        if (prev == EBPH_EMPTY)
            break;

        /* determine which entry we need */
        entry = ebpH_get_lookahead_index(&syscall, &prev, ctx);

        if (entry == -1)
            continue;

        /* lookup the syscall data */
        u8 the_entry = data->flags[entry];

        /* check for mismatch */
        if ((the_entry & (1 << (i-1))) == 0)
        {
            mismatches++;
        }
    }

    return mismatches;
}

static int ebpH_train(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    /* update train_count and last_mod_count */
    profile->train.train_count++;
    if (ebpH_test(&(profile->train), process, ctx))
    {
        if (profile->frozen)
            profile->frozen = 0;
        ebpH_add_seq(profile, process, ctx);
        profile->train.last_mod_count = 0;

#ifdef EBPH_DEBUG
        bpf_trace_printk("New LAP(s) generated for %s by the following sequence [curr->prev]:\n", profile->comm);
        for (int i = 1; i < EBPH_SEQLEN; i++)
            bpf_trace_printk("|   System call %ld\n", process->seq[i]);
#endif
    }
    else
    {
        profile->train.last_mod_count++;

        if (profile->frozen)
            return 0;

        // FIXME: we won't need this when we have proper locking
        if (profile->train.last_mod_count > profile->train.train_count)
            profile->train.last_mod_count = profile->train.train_count;

        profile->train.normal_count = profile->train.train_count - profile->train.last_mod_count;

        if ((profile->train.normal_count > 0) && (profile->train.train_count * EBPH_NORMAL_FACTOR_DEN >
                    profile->train.normal_count * EBPH_NORMAL_FACTOR))
        {
            profile->frozen = 1;
            ebpH_set_normal_time(profile, ctx);
        }
    }

    return 0;
}

static int ebpH_start_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    ebpH_copy_train_to_test(profile);

    profile->normal = 1;
    profile->frozen = 0;
    profile->anomalies = 0;
    profile->train.last_mod_count = 0;
    profile->train.train_count = 0;

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
        process->alf.win[i] = 0;
    }

    process->alf.total = 0;
    process->alf.max = 0;
    process->alf.first = 0;

    /* TODO: zero out delay here */

    return 0;
}

static int ebpH_add_seq(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    long entry = -1;
    long syscall = 0;
    long prev = 0;

    if (!process || process->count < 1)
        return 0;

    /* Access at index [syscall][prev] */
    for (int i = 1; i < EBPH_SEQLEN; i++)
    {
        syscall = process->seq[0];
        prev = process->seq[i];
        if (prev == EBPH_EMPTY)
            break;

        /* Determine which entry we need */
        entry = ebpH_get_lookahead_index(&syscall, &prev, ctx);

        if (entry == -1)
            continue;

        /* Lookup the syscall data */
        u8 data = profile->train.flags[entry];

        /* Set lookahead pair */
        data |= (1 << (i - 1));
        profile->train.flags[entry] = data;
    }

    return 0;
}

static int ebpH_add_anomaly_count(struct ebpH_profile *profile, struct ebpH_process *process, int count, struct pt_regs *ctx)
{
    int curr = process->alf.first;
    int next = (process->alf.first + 1) % EBPH_LOCALITY_WIN;

    /* All buffer and no check makes verifier a dull boy */
    if (curr >= EBPH_LOCALITY_WIN || curr < 0 || next >= EBPH_LOCALITY_WIN || next < 0)
    {
        EBPH_ERROR("Access would be out of bounds -- ebpH_add_anomaly_count", ctx);
        return 1;
    }

    if (count > 0)
    {
        profile->anomalies++;
        if (process->alf.win[curr] == 0)
        {
            process->alf.win[curr] = 1;
            process->alf.total++;
            if (process->alf.total > process->alf.max)
                process->alf.max = process->alf.total;
        }
    }
    else if (process->alf.win[curr] > 0)
    {
        process->alf.win[curr] = 0;
        process->alf.total--;
    }
    process->alf.first = next;

    return 0;
}

static int ebpH_process_syscall(struct ebpH_process *process, long *syscall, struct pt_regs *ctx)
{
    struct ebpH_profile *profile;
    int *monitoring, *saving;
    int zero = 0;
    int lfc = 0;

    if (!process)
    {
        EBPH_ERROR("NULL process -- ebpH_process_syscall", ctx);
        return 1;
    }

    if (!syscall)
    {
        EBPH_ERROR("NULL syscall -- ebpH_process_syscall", ctx);
        return 1;
    }

    if (!process->exe_key)
    {
        return 0;
    }

    monitoring = __is_monitoring.lookup(&zero);
    saving = __is_saving.lookup(&zero);

    if (!saving || !monitoring)
    {
        return 0;
    }

    if (*saving)
    {
        *monitoring = 0;
        __is_monitoring.update(&zero, monitoring);
    }

    if (!(*monitoring))
    {
        return 0;
    }

    profile = profiles.lookup(&(process->exe_key));

    if (!profile)
    {
        ebpH_debug_int.perf_submit(ctx, &process->exe_key, sizeof(process->exe_key));
        EBPH_ERROR("NULL profile -- ebpH_process_syscall", ctx);
        bpf_trace_printk("NULL profile for key %lu -- ebpH_process_syscall\n", process->exe_key);
        return 1;
    }

    /* Add syscall to process sequence */
    for (int i = EBPH_SEQLEN - 1; i > 0; i--)
    {
        process->seq[i] = process->seq[i-1];
    }
    process->seq[0] = *syscall;
    process->count = process->count < EBPH_SEQLEN ? process->count + 1 : process->count;

    /* TODO: take profile lock here */

    ebpH_train(profile, process, ctx);

    /* Update normal status if we are frozen and have reached normal_time */
    if (ebpH_check_normal_time(profile, ctx))
    {
        ebpH_start_normal(profile, process, ctx);
    }

    ebpH_process_normal(profile, process, ctx);

    lfc = process->alf.total;
    if (lfc > EBPH_TOLERIZE_LIMIT)
    {
        ebpH_reset_profile_data(&(profile->train), ctx);
    }

    /* TODO: release profile lock here */

    /* TODO: delay task here */

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

/* Return the group leader process id of the task making the current systemcall.
 * This is useful for when we need to copy the task leader process' profile during a clone. */
static u64 ebpH_get_glpid_tgid()
{
    u64 glpid_tgid;
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    glpid_tgid = ((u64)task->group_leader->tgid << 32) | (u64)task->group_leader->pid;

    return glpid_tgid;
}

/* Create a process struct for the given pid if it doesn't exist */
static int ebpH_create_process(u64 *pid_tgid, struct pt_regs *ctx)
{
    int zero = 0;
    struct ebpH_process *process;

    /* Process already exists */
    if (processes.lookup(pid_tgid))
        return 0;

    /* Get the address of the zeroed executable struct */
    process = __process_init.lookup(&zero);

    if (!process)
    {
        EBPH_ERROR("NULL process -- ebpH_create_process", ctx);
        return 1;
    }

    /* Copy memory over */
    process = processes.lookup_or_try_init(pid_tgid, process);
    if (!process)
    {
        EBPH_ERROR("Could not add process to processes map -- ebpH_create_process", ctx);
        return 1;
    }

    process->pid = (*pid_tgid) >> 32;
    process->tid = (*pid_tgid);
    for (int i = 0; i < EBPH_SEQLEN; i++)
        process->seq[i] = EBPH_EMPTY;

    return 0;
}

/* Associate process struct with the correct PID and the correct profile */
static int ebpH_start_tracing(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    if (!process)
    {
        EBPH_ERROR("NULL process -- ebpH_start_tracing", ctx);
        return 1;
    }

    if (!profile)
    {
        EBPH_ERROR("NULL profile -- ebpH_start_tracing", ctx);
        return 1;
    }

    process->exe_key = profile->key;

    return 0;
}

/* Create a profile if one does not already exist. */
static int ebpH_create_profile(u64 *key, char *comm, u8 in_execve, struct pt_regs *ctx)
{
    int zero = 0;
    struct ebpH_profile *profile = NULL;

    if (in_execve)
        return 1;

    if (!key)
    {
        EBPH_ERROR("NULL key -- ebpH_create_profile", ctx);
        return 1;
    }

    if (!comm)
    {
        EBPH_ERROR("NULL comm -- ebpH_create_profile", ctx);
        return 1;
    }

    /* If the profile for this key already exists, move on */
    profile = profiles.lookup(key);
    if (profile)
    {
        return 0;
    }

    /* Get the address of the zeroed executable struct */
    profile = __profile_init.lookup(&zero);

    if (!profile)
    {
        EBPH_ERROR("NULL init -- ebpH_create_profile", ctx);
        return 1;
    }

    /* Copy memory over */
    profile = profiles.lookup_or_try_init(key, profile);
    if (!profile)
    {
        EBPH_ERROR("Could not add profile to profiles map -- ebpH_create_profile", ctx);
        return 1;
    }

    profile->key = *key;
    bpf_probe_read_str(profile->comm, sizeof(profile->comm), comm);
    ebpH_set_normal_time(profile, ctx);

    /* Send info to userspace for logging */
    struct info
    {
        char comm[EBPH_FILENAME_LEN];
        u64 key;
    };
    struct info info = {};
    info.key = profile->key;
    bpf_probe_read_str(info.comm, sizeof(info.comm), profile->comm);
    on_executable_processed.perf_submit(ctx, &info, sizeof(info));

    return 0;
}

static int ebpH_copy_train_to_test(struct ebpH_profile *profile)
{
        struct ebpH_profile_data *train = &(profile->train);
        struct ebpH_profile_data *test = &(profile->test);
        int i;

        //test->sequences = train->sequences;
        test->last_mod_count = train->last_mod_count;
        test->train_count = train->train_count;

        for (i = 0; i < EBPH_LOOKAHEAD_ARRAY_SIZE; i++) {
            test->flags[i] = train->flags[i];
        }

        return 0;
}

static int ebpH_reset_profile_data(struct ebpH_profile_data *data, struct pt_regs *ctx)
{
    u8 zero = 0;
    bpf_probe_read(data->flags, sizeof(data->flags), &zero);

    return 0;
}

/* Tracepoints and kprobes below this line --------------------- */

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    long syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ebpH_process *process;

    int zero = 0;
    int *monitoring = __is_monitoring.lookup(&zero);

    if (!monitoring)
    {
        return 0;
    }

    if (!(*monitoring))
    {
        return 0;
    }

    process = processes.lookup(&pid_tgid);

    /* Process does not already exist */
    if (!process)
    {
        return 0;
    }

    /* The juicy stuff goes right here */
    ebpH_process_syscall(process, &syscall, (struct pt_regs *)args);

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    long syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ppid_tgid = ebpH_get_ppid_tgid();
    u64 glpid_tgid = ebpH_get_glpid_tgid();
    u64 key = 0;
    struct ebpH_profile *e;
    struct ebpH_process *process;
    struct ebpH_process *parent_process;

    int zero = 0;
    int *monitoring = __is_monitoring.lookup(&zero);

    if (!monitoring)
    {
        return 0;
    }

    if (!(*monitoring))
    {
        return 0;
    }

    if (syscall == __NR_execve || syscall == __NR_execveat)
    {
        process = processes.lookup(&pid_tgid);
        if (!process)
        {
            return 0;
        }
        process->in_execve = 0;

        /* Wipe process' current sequence */
        for (int i = 0; i < EBPH_SEQLEN; i++)
        {
            process->seq[i] = EBPH_EMPTY;
        }
        process->count = 0;
    }

    /* Associate pids on fork */
    if (syscall == __NR_fork || syscall == __NR_vfork || syscall == __NR_clone)
    {
        /* We want to be in the child process...
         * fork/vfork and clone handle this differently. */
        if ((syscall == __NR_fork || syscall == __NR_vfork) && args->ret != 0)
            return 0;
        //if (syscall == __NR_clone)
        //    return 0; /* FIXME: For now... */

        ebpH_create_process(&pid_tgid, (struct pt_regs *)args);
        process = processes.lookup(&pid_tgid);

        if (!process)
        {
            /* We should never ever get here! */
            EBPH_ERROR("Unable to map process -- sys_exit", (struct pt_regs *) args);
            return 0;
        }

        /* Check if we are tracing its parent process or thread group leader */
        if (syscall == __NR_clone) /* FIXME: check for threaded */
        {
            parent_process = processes.lookup(&glpid_tgid);
        }
        else /* fork, vfork, on non-threaded clone */
        {
            parent_process = processes.lookup(&ppid_tgid);
        }
        if (!parent_process || !parent_process->exe_key)
        {
            /* FIXME: This message is annoying. It will be more relevant when we are actually
             * starting the daemon on system startup. For now, we can comment it out. */
            //EBPH_WARNING("No data to copy to child process -- sys_exit", (struct pt_regs *)args);
            processes.delete(&pid_tgid);
            return 0;
        }

        key = parent_process->exe_key;
        e = profiles.lookup(&key);
        if (!e)
        {
            /* We should never ever get here! */
            EBPH_ERROR("A key has become detached from its binary -- sys_exit", (struct pt_regs *)args);
            return 0;
        }

        /* Copy parent process' sequence to child */
        for (int i = 0; i < EBPH_SEQLEN; i++)
        {
            process->seq[i] = parent_process->seq[i];
        }
        process->count = parent_process->count;

        /* Associate process with its parent profile */
        ebpH_start_tracing(e, process, (struct pt_regs *)args);
    }

    return 0;
}

/* When a process or thread exits */
TRACEPOINT_PROBE(sched, sched_process_exit)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    processes.delete(&pid_tgid);

    return 0;
}

/* This is a special hook for execve-family calls
 * We need to inspect do_open_execat to snag information about the file
 * If this breaks in a future version of Linux (definitely possible!), I will be sad :( */
int kretprobe__do_open_execat(struct pt_regs *ctx)
{
    struct file *exec_file;
    struct dentry *exec_entry;
    struct inode *exec_inode;
    char comm[EBPH_FILENAME_LEN];
    u64 key = 0;
    struct ebpH_process *process = NULL;
    struct ebpH_profile *profile = NULL;

    int zero = 0;
    int *monitoring = __is_monitoring.lookup(&zero);

    if (!monitoring)
    {
        return 0;
    }

    if (!(*monitoring))
    {
        return 0;
    }


    /* Yoink the file struct */
    exec_file = (struct file *)PT_REGS_RC(ctx);
    if (!exec_file || IS_ERR(exec_file))
    {
        /* If the file doesn't exist (invalid execve call), just return here */
        return 0;
    }

    /* Fetch dentry for executable */
    exec_entry = exec_file->f_path.dentry;
    if (!exec_entry)
    {
        EBPH_ERROR("Couldn't fetch the dentry for this executable -- ebpH_on_do_open_execat", ctx);
        return 0;
    }

    /* Fetch inode for executable */
    exec_inode = exec_entry->d_inode;
    if (!exec_inode)
    {
        EBPH_ERROR("Couldn't fetch the inode for this executable -- ebpH_on_do_open_execat", ctx);
        return 0;
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

    /* Create the process if it doesn't already exist */
    ebpH_create_process(&pid_tgid, ctx);
    process = processes.lookup(&pid_tgid);
    if (!process)
    {
        EBPH_ERROR("NULL process, cannot start tracing --  ebpH_on_do_open_execat", ctx);
        return 0;
    }

    /* If we are already in an execve, we don't want to go any further */
    if (process->in_execve)
        return 0;

    /* Create a profile if necessary */
    ebpH_create_profile(&key, comm, process->in_execve, ctx);
    process->in_execve = 1;

    /* Start tracing the process */
    profile = profiles.lookup(&key);
    if (!profile)
    {
        EBPH_ERROR("NULL profile, cannot start tracing --  ebpH_on_do_open_execat", ctx);
        return 0;
    }
    ebpH_start_tracing(profile, process, ctx);

    return 0;
}
