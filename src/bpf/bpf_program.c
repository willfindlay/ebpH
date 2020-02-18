/* ebpH An eBPF intrusion detection program.
 * Monitors system call patterns and detects anomalies.
 * Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
 * Anil Somayaji (soma@scs.carleton.ca)
 *
 * Based on Anil Somayaji's pH
 *  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
 *  Copyright 2003 Anil Somayaji
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

/* Main syscall event buffer */
BPF_PERF_OUTPUT(on_executable_processed);
BPF_PERF_OUTPUT(on_pid_assoc);
BPF_PERF_OUTPUT(on_anomaly);
BPF_PERF_OUTPUT(on_new_sequence);

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

/* tid to ebpH_process */
BPF_F_TABLE("hash", u32, struct ebpH_process, processes, EBPH_PROCESSES_TABLE_SIZE, BPF_F_NO_PREALLOC);
//BPF_F_TABLE("lru_hash", u64, struct ebpH_process, processes, EBPH_PROCESSES_TABLE_SIZE, 0);

/* profile key to ebpH_profile */
BPF_F_TABLE("hash", u64, struct ebpH_profile, profiles, EBPH_PROFILES_TABLE_SIZE, BPF_F_NO_PREALLOC);
//BPF_F_TABLE("lru_hash", u64, struct ebpH_profile, profiles, EBPH_PROFILES_TABLE_SIZE, 0);

/* Statistics histogram (stat, key, size)*/
BPF_HISTOGRAM(stats, u8, 2);

/* WARNING: These maps are READ-ONLY */
BPF_ARRAY(__profile_init, struct ebpH_profile, 1);
BPF_ARRAY(__process_init, struct ebpH_process, 1);

/* Store program state */
BPF_ARRAY(__is_saving, int, 1);
BPF_ARRAY(__is_monitoring, int, 1);
BPF_ARRAY(__is_logging_new_sequences, int, 1);

/* Function definitions below this line --------------------- */

/* WARNING: Be cautious of overflows */
static void stats_increment(u8 key)
{
    u64 zero = 0;
    u64 *leaf = stats.lookup_or_try_init(&key, &zero);

    if (!leaf)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("stats_increment: Null leaf for key %u\n", key);
        #endif
        return;
    }

    if (*leaf == (~(u64)0))
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("stats_increment: Cannot increment leaf value of %llu for key %u\n", *leaf, key);
        #endif
        return;
    }

    (void) __sync_fetch_and_add(leaf, 1);
}

/* WARNING: Be cautious of underflows */
static void stats_decrement(u8 key)
{
    u64 zero = 0;
    u64 *leaf = stats.lookup_or_try_init(&key, &zero);

    if (!leaf)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("stats_decrement: Null leaf for key %u\n", key);
        #endif
        return;
    }

    if (*leaf <= 0)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("stats_decrement: Cannot decrement leaf value of %llu for key %u\n", *leaf, key);
        #endif
        return;
    }

    (void) __sync_fetch_and_sub(leaf, 1);
}

static u64 ebpH_epoch_time_ns()
{
    return (u64) bpf_ktime_get_ns() + EBPH_BOOT_EPOCH;
}

/* Return the thread ID of the current task. */
static u32 ebpH_get_tid()
{
    return (u32)bpf_get_current_pid_tgid();
}

/* Return the parent process id of the task making the current systemcall.
 * This is useful for when we need to copy the parent process' profile during a fork. */
static u32 ebpH_get_parent_tid()
{
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    return task->real_parent->pid;
}

/* Return the group leader process id of the task making the current systemcall.
 * This is useful for when we need to copy the group leader process' profile after a clone. */
static u32 ebpH_get_group_leader_tid()
{
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    return task->group_leader->pid;
}

static u8 *ebpH_lookahead(struct ebpH_profile_data *data, long curr, long prev)
{
    /* Null profile data */
    if (!data)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_lookahead: Null profile data\n");
        #endif
        return NULL;
    }

    /* Invalid access */
    if (curr < 0 || curr >= EBPH_NUM_SYSCALLS)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_lookahead: Invalid curr value %ld\n", curr);
        #endif
        return NULL;
    }

    struct ebpH_lookahead_row *row = &data->rows[curr];

    /* Invalid access */
    if (!row || prev < 0 || prev >= EBPH_NUM_SYSCALLS)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_lookahead: Invalid prev value %ld\n", prev);
        #endif
        return NULL;
    }

    return &row->flags[prev];
}

static int ebpH_push_seq(struct ebpH_process *process)
{
    if (!process)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_push_seq: Null process\n");
        #endif
        return -1;
    }

    if (process->stack.top == EBPH_SEQSTACK_SIZE - 1)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_push_seq: Cannot push to stack since top is %d\n", process->stack.top);
        #endif
        return -2;
    }

    /* Increment top if we can */
    process->stack.top++;

    struct ebpH_sequence *seq = ebpH_curr_seq(process);
    if (!seq)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_push_seq: Null sequence\n");
        #endif
        return -3;
    }

    /* Reinitialize the sequence */
    seq->count = 0;
    for (int i = 0; i < EBPH_SEQLEN; i++)
        seq->seq[i] = EBPH_EMPTY;

    return 0;
}

static int ebpH_pop_seq(struct ebpH_process *process)
{
    /* Check to see if process is null */
    if (!process)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_pop_seq: Null process\n");
        #endif
        return -1;
    }

    /* Check to see if we can decrement top of stack */
    if (process->stack.top == 0)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_pop_seq: Cannot pop from stack, top is %d\n", process->stack.top);
        #endif
        return -2;
    }

    /* Decrement top */
    process->stack.top--;

    return 0;
}

static struct ebpH_sequence *ebpH_curr_seq(struct ebpH_process *process)
{
    /* Check to see if process is null */
    if (!process)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_curr_seq: Null process\n");
        #endif
        return NULL;
    }

    /* Check for invalid access */
    if (process->stack.top < 0 || process->stack.top >= EBPH_SEQSTACK_SIZE)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_curr_seq: Invalid stack access, top is %d\n", process->stack.top);
        #endif
        return NULL;
    }

    return &process->stack.seq[process->stack.top];
}

static int ebpH_process_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    int anomalies = 0;

    if (profile->normal)
    {
        anomalies = ebpH_test(&(profile->test), process, ctx);
        if (anomalies)
        {
            struct ebpH_sequence *seq = ebpH_curr_seq(process);
            if (!seq)
            {
                #ifdef EBPH_DEBUG
                bpf_trace_printk("ebpH_process_normal: Null sequence, cannot submit anomaly event\n");
                #endif
                // TODO: call EBPH_ERROR here
                goto out;
            }

            on_anomaly.perf_submit(ctx, process, sizeof(*process));
            // TODO: check for successful submission here

            if (profile->anomalies > EBPH_ANOMALY_LIMIT)
            {
                ebpH_stop_normal(profile, process, ctx);
            }
        }
    }

out:
    ebpH_add_anomaly_count(profile, process, anomalies, ctx);

    return 0;
}

static int ebpH_test(struct ebpH_profile_data *data, struct ebpH_process *process, struct pt_regs *ctx)
{
    u8 *entry;
    int mismatches = 0;

    if (!process)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_test: Null process\n");
        #endif
        return 0;
    }

    struct ebpH_sequence *seq = ebpH_curr_seq(process);

    if (!seq)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_test: Null sequence\n");
        #endif
        return 0;
    }

    /* Sequence is empty. Obviously not considered an error */
    if (!seq->count)
    {
        return 0;
    }

    /* Check every (curr, prev) pair for current syscall */
    for (int i = 1; i < EBPH_SEQLEN; i++)
    {
        long curr = seq->seq[0];
        long prev = seq->seq[i];
        if (prev == EBPH_EMPTY)
            break;

        /* determine which entry we need */
        entry = ebpH_lookahead(data, curr, prev);

        if (!entry)
        {
            #ifdef EBPH_DEBUG
            bpf_trace_printk("ebpH_test: Null entry at (curr, prev) = (%ld, %ld)\n", curr, prev);
            #endif
            continue;
        }

        /* check for mismatch */
        if ((*entry & (1 << (i-1))) == 0)
        {
            mismatches++;
        }
    }

    return mismatches;
}

static int ebpH_train(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    /* update train_count and last_mod_count */
    lock_xadd(&profile->train.train_count, 1);
    if (ebpH_test(&(profile->train), process, ctx))
    {
        if (profile->frozen)
            profile->frozen = 0;
        ebpH_add_seq(profile, process, ctx);
        profile->train.last_mod_count = 0;

        int zero = 0;
        int *logging_new_sequences = __is_logging_new_sequences.lookup(&zero);
        if (logging_new_sequences && *logging_new_sequences)
        {
            on_new_sequence.perf_submit(ctx, process, sizeof(*process));
        }
    }
    else
    {
        lock_xadd(&profile->train.last_mod_count, 1);

        if (profile->frozen)
            return 0;

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
    u64 time_ns = ebpH_epoch_time_ns();
    time_ns += EBPH_NORMAL_WAIT;

    profile->normal_time = time_ns;

    return 0;
}

static int ebpH_check_normal_time(struct ebpH_profile *profile, struct pt_regs *ctx)
{
    u64 time_ns = ebpH_epoch_time_ns();
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
    u8 *entry;

    if (!process)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_add_seq: Null process\n");
        #endif
        return -1;
    }

    struct ebpH_sequence *seq = ebpH_curr_seq(process);

    if (!seq)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_add_seq: Null sequence\n");
        #endif
        return -2;
    }

    /* Sequence is empty. Obviously not considered an error */
    if (!seq->count)
    {
        return 0;
    }

    /* Set every (curr, prev) pair for current syscall */
    for (int i = 1; i < EBPH_SEQLEN; i++)
    {
        long curr = seq->seq[0];
        long prev = seq->seq[i];
        if (prev == EBPH_EMPTY)
            break;

        /* Determine which entry we need */
        entry = ebpH_lookahead(&profile->train, curr, prev);

        if (!entry)
        {
            #ifdef EBPH_DEBUG
            bpf_trace_printk("ebpH_add_seq: Null entry at (curr, prev) = (%ld, %ld)\n", curr, prev);
            #endif
            continue;
        }

        /* Set lookahead pair */
        *entry |= (1 << (i - 1));
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
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_add_anomaly_count: Inavlid access at (curr, next) = (%d, %d)\n", curr, next);
        #endif
        return -1;
    }

    if (count > 0)
    {
        lock_xadd(&profile->anomalies, 1);
        if (process->alf.win[curr] == 0)
        {
            process->alf.win[curr] = 1;
            lock_xadd(&process->alf.total, 1);
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
        EBPH_ERROR("ebpH_process_syscall: Null process", ctx);
        return -1;
    }

    if (!syscall)
    {
        EBPH_ERROR("ebpH_process_syscall: Null syscall", ctx);
        return -1;
    }

    if (!process->profile_key)
    {
        EBPH_ERROR("ebpH_process_syscall: Null profile_key", ctx);
        return -1;
    }

    monitoring = __is_monitoring.lookup(&zero);
    saving = __is_saving.lookup(&zero);

    if (!monitoring)
    {
        EBPH_ERROR("ebpH_process_syscall: Could not determine value for \"monitoring\"", ctx);
        return -1;
    }

    if (!saving)
    {
        EBPH_ERROR("ebpH_process_syscall: Could not determine value for \"saving\"", ctx);
        return -1;
    }

    if (!(*monitoring) || (*saving))
    {
        return 0;
    }

    profile = profiles.lookup(&(process->profile_key));

    if (!profile)
    {
        EBPH_ERROR("ebpH_process_syscall: Null profile", ctx);
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_process_syscall: Null profile for key %llu\n", process->profile_key);
        #endif
        return -1;
    }

    struct ebpH_sequence *seq = ebpH_curr_seq(process);

    if (!seq)
    {
        EBPH_ERROR("ebpH_process_syscall: Null sequence", ctx);
        return -1;
    }

    /* Add syscall to process sequence */
    for (int i = EBPH_SEQLEN - 1; i > 0; i--)
    {
        seq->seq[i] = seq->seq[i-1];
    }
    seq->seq[0] = *syscall;
    seq->count = seq->count < EBPH_SEQLEN ? seq->count + 1 : seq->count;

    // TODO: add optional support for logging all sequences here

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
        // TODO: notify user here
    }

    /* TODO: release profile lock here */

    /* TODO: delay task here */

    return 0;
}

/* Create a process struct for the given tid if it doesn't exist */
static int ebpH_create_process(u32 *tid, struct pt_regs *ctx)
{
    int zero = 0;
    struct ebpH_process *process;

    /* Process already exists */
    if (processes.lookup(tid))
    {
        return 0;
    }

    /* Get the address of the zeroed executable struct */
    process = __process_init.lookup(&zero);

    if (!process)
    {
        EBPH_ERROR("ebpH_create_process: Could not fetch init template for process", ctx);
        return -1;
    }

    /* Copy memory over */
    process = processes.lookup_or_try_init(tid, process);
    if (!process)
    {
        EBPH_ERROR("ebpH_create_process: Unable to add process to map", ctx);
        return -1;
    }

    process->pid = ebpH_get_group_leader_tid();
    process->tid = *tid;
    for (int i = 0; i < EBPH_SEQSTACK_SIZE; i++)
    {
        for (int j = 0; j < EBPH_SEQLEN; j++)
            process->stack.seq[i].seq[j] = EBPH_EMPTY;
    }

    return 0;
}

/* Associate process struct with the correct PID and the correct profile */
static int ebpH_start_tracing(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    if (!process)
    {
        EBPH_ERROR("ebpH_start_tracing: Null process", ctx);
        return -1;
    }

    if (!profile)
    {
        EBPH_ERROR("ebpH_start_tracing: Null profile", ctx);
        return 1;
    }

    process->profile_key = profile->key;

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
        EBPH_ERROR("ebpH_create_profile: Null key", ctx);
        return 1;
    }

    if (!comm)
    {
        EBPH_ERROR("ebpH_create_profile: Null comm", ctx);
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
        EBPH_ERROR("ebpH_create_profile: Could not fetch init template for profile", ctx);
        return 1;
    }

    /* Copy memory over */
    profile = profiles.lookup_or_try_init(key, profile);
    if (!profile)
    {
        EBPH_ERROR("ebpH_create_profile: Unable to add profile to map", ctx);
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
    bpf_probe_read(test, sizeof(*test), train);

    return 0;
}

static int ebpH_reset_profile_data(struct ebpH_profile_data *data, struct pt_regs *ctx)
{
    u8 zero = 0;
    bpf_probe_read(data->rows, sizeof(data->rows), &zero);

    return 0;
}

/* Tracepoints and kprobes below this line --------------------- */

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    long syscall = args->id;
    u32 tid = ebpH_get_tid();
    struct ebpH_process *process;

    int zero = 0;
    int *monitoring = __is_monitoring.lookup(&zero);

    if (!monitoring)
    {
        EBPH_ERROR("raw_syscalls:sys_enter: Could not determine value for \"monitoring\"", (struct pt_regs *)args);
        return -1;
    }

    if (!(*monitoring))
    {
        return 0;
    }

    process = processes.lookup(&tid);

    /* Process does not already exist */
    if (!process)
    {
        return 0;
    }

    stats_increment(STATS_SYSCALLS);

    /* Pop if we are flagged for popping
     * See below */
    if (process->stack.should_pop)
    {
        process->stack.should_pop = 0;
        if (ebpH_pop_seq(process))
        {
            EBPH_ERROR("raw_syscalls:sys_enter: Failed to pop sequence from stack", (struct pt_regs *)args);
            return -1;
        }
    }

    /* Flag for pop on sigreturn
     * We actually want to pop on the NEXT systemcall */
    if (syscall == __NR_rt_sigreturn)
    {
        process = processes.lookup(&tid);
        if (!process)
        {
            return 0;
        }

        process->stack.should_pop = 1;
    }

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    long syscall = args->id;
    u32 tid = ebpH_get_tid();
    u32 ptid = ebpH_get_parent_tid();
    u32 gltid = ebpH_get_group_leader_tid();
    struct ebpH_profile *profile;
    struct ebpH_process *process;
    struct ebpH_process *parent_process;

    int zero = 0;
    int *monitoring = __is_monitoring.lookup(&zero);

    if (!monitoring)
    {
        EBPH_ERROR("raw_syscalls:sys_exit: Could not determine value for \"monitoring\"", (struct pt_regs *)args);
        return -1;
    }

    if (!(*monitoring))
    {
        return 0;
    }

    // TODO: figure out why some numbers are negative (likely for system calls that don't return)
    if (args->id < 0)
    {
        return 0;
    }

    /* Associate task with profile on execve */
    if (syscall == __NR_execve || syscall == __NR_execveat)
    {
        process = processes.lookup(&tid);

        if (!process)
        {
            return 0;
        }

        process->in_execve = 0;

        /* Reset process' sequence stack */
        for (int i = 0; i < EBPH_SEQSTACK_SIZE; i++)
        {
            process->stack.seq[i].count = 0;
            for (int j = 0; j < EBPH_SEQLEN; j++)
            {
                process->stack.seq[i].seq[j] = EBPH_EMPTY;
            }
        }
    }

    /* Associate pids on fork, vfork, clone */
    if (syscall == __NR_fork || syscall == __NR_vfork || syscall == __NR_clone)
    {
        /* We want to be in the child process...
         * fork/vfork and clone handle this differently. */
        if ((syscall == __NR_fork || syscall == __NR_vfork) && args->ret != 0)
        {
            return 0;
        }

        ebpH_create_process(&tid, (struct pt_regs *)args);
        process = processes.lookup(&tid);

        if (!process)
        {
            /* We should never ever get here! */
            EBPH_ERROR("raw_syscalls:sys_exit: Unable to lookup process", (struct pt_regs *) args);
            return -1;
        }

        /* Check if we are tracing its parent process or thread group leader */
        if (syscall == __NR_clone) /* FIXME: check for threaded */
        {
            parent_process = processes.lookup(&gltid);
        }
        else /* fork, vfork, on non-threaded clone */
        {
            parent_process = processes.lookup(&ptid);
        }
        if (!parent_process || !parent_process->profile_key)
        {
            /* FIXME: This message is annoying. It will be more relevant when we are actually
             * starting the daemon on system startup. For now, we can comment it out. */
            //EBPH_WARNING("No data to copy to child process -- sys_exit", (struct pt_regs *)args);
            processes.delete(&tid);
            return 0;
        }

        profile = profiles.lookup(&parent_process->profile_key);
        if (!profile)
        {
            /* We should never ever get here! */
            EBPH_ERROR("raw_syscalls:sys_exit: Unable to lookup profile", (struct pt_regs *)args);
            return -1;
        }

        /* Copy parent process' sequences to child
         * and reset process' sequence stack */
        for (int i = 0; i < EBPH_SEQSTACK_SIZE; i++)
        {
            process->stack.seq[i].count = parent_process->stack.seq[i].count;
            for (int j = 0; j < EBPH_SEQLEN; j++)
            {
                process->stack.seq[i].seq[j] = parent_process->stack.seq[i].seq[j];
            }
        }

        /* Associate process with its parent profile */
        ebpH_start_tracing(profile, process, (struct pt_regs *)args);
    }

    process = processes.lookup(&tid);
    if (!process)
    {
        return 0;
    }

    /* Process syscall if it won't be restarted */
    if (args->ret != -ERESTARTSYS && args->ret != -ERESTARTNOHAND
            && args->ret != -ERESTARTNOINTR && args->ret != -ERESTART_RESTARTBLOCK)
    {
        ebpH_process_syscall(process, &syscall, (struct pt_regs *)args);
    }
    else
    {
        // TODO: consider removing this print completely
        //#ifdef EBPH_DEBUG
        //bpf_trace_printk("raw_syscalls:sys_exit: Refusing to process syscall %d since it will be restarted.\n", syscall);
        //#endif
    }

    return 0;
}

/* When a process or thread exits */
TRACEPOINT_PROBE(sched, sched_process_exit)
{
    u32 tid = ebpH_get_tid();
    processes.delete(&tid);

    return 0;
}

/* Exit hook for execve implementation in order to get useful information about
 * the opened executable file */
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
        EBPH_ERROR("kretprobe__do_open_execat: Could not determine value for \"monitoring\"", ctx);
        return -1;
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
        EBPH_ERROR("kretprobe__do_open_execat: Couldn't fetch the dentry for this executable", ctx);
        return -1;
    }

    /* Fetch inode for executable */
    exec_inode = exec_entry->d_inode;
    if (!exec_inode)
    {
        EBPH_ERROR("kretprobe__do_open_execat: Couldn't fetch the inode for this executable", ctx);
        return -1;
    }

    /* We want a key to be comprised of device number in the upper 32 bits
     * and inode number in the lower 32 bits */
    key  = exec_inode->i_ino;
    key |= ((u64)exec_inode->i_rdev << 32);

    u32 tid = ebpH_get_tid();

    /* Load executable name into comm */
    struct qstr dn = {};
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&dn, sizeof(dn), &exec_entry->d_name);
    bpf_probe_read(&comm, sizeof(comm), dn.name);

    /* Create the process if it doesn't already exist */
    ebpH_create_process(&tid, ctx);
    process = processes.lookup(&tid);
    if (!process)
    {
        EBPH_ERROR("kretprobe__do_open_execat: Unable to lookup process", ctx);
        return -1;
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
        EBPH_ERROR("kretprobe__do_open_execat: Unable to lookup profile", ctx);
        return 0;
    }
    ebpH_start_tracing(profile, process, ctx);

    return 0;
}

/* Entry hook for kernel signal handler implementation */
int kprobe__do_signal(struct pt_regs *ctx)
{
    u32 tid = ebpH_get_tid();
    struct ebpH_process *process = processes.lookup(&tid);

    if (!process)
    {
        /* Process is not being traced */
        return 0;
    }

    if (ebpH_push_seq(process))
    {
        EBPH_ERROR("kprobe__do_signal: Failed to push sequence onto stack", ctx);
        return -1;
    }

    return 0;
}

int cmd_normalize(struct pt_regs *ctx)
{
    u32 tid = (u32)PT_REGS_PARM1(ctx);

    struct ebpH_process *process = processes.lookup(&tid);
    if (!process)
    {
        EBPH_ERROR("cmd_start_normal: No such process", ctx);
        return -1;
    }

    struct ebpH_profile *profile = profiles.lookup(&process->profile_key);
    if (!profile)
    {
        EBPH_ERROR("cmd_start_normal: No such profile", ctx);
        return -1;
    }

    ebpH_start_normal(profile, process, ctx);

    return 0;
}
