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
#include <linux/kdev_t.h>
#include <linux/binfmts.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/timekeeping.h>
#include <uapi/linux/ptrace.h>
#include <uapi/asm/unistd_64.h>

#include "bpf/defs.h"
#include "bpf/bpf_program.h"

#define EBPH_ERROR(MSG, CTX) char m[] = (MSG); __ebpH_log_error(m, sizeof(m), (CTX))
#define EBPH_WARNING(MSG, CTX) char m[] = (MSG); __ebpH_log_warning(m, sizeof(m), (CTX))

/* TODO: deprecate some of these */
BPF_PERF_OUTPUT(ebpH_error);
BPF_PERF_OUTPUT(ebpH_warning);

/* Main syscall event buffer */
BPF_PERF_OUTPUT(on_executable_processed);
BPF_PERF_OUTPUT(on_anomaly);
BPF_PERF_OUTPUT(on_anomaly_limit);
BPF_PERF_OUTPUT(on_tolerize_limit);
BPF_PERF_OUTPUT(on_start_normal);
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

/* pid (kernel pid) to ebpH_process */
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

static inline u32 ebpH_get_pid()
{
    u32 pid = bpf_get_current_pid_tgid();
    return pid;
}

static inline u32 ebpH_get_tgid()
{
    u32 tgid = (bpf_get_current_pid_tgid() >> 32);
    return tgid;
}

// FIXME: error logging here causes back edge, need to figure out why
static __always_inline u32 ebpH_lookahead_index(struct ebpH_profile_data *data, u32 curr, u32 prev)
{
    /* Null profile data */
    if (!data)
    {
        /* #ifdef EBPH_DEBUG */
        /* bpf_trace_printk("ebpH_lookahead_index: Null profile data\n"); */
        /* #endif */
        return 0;
    }

    /* Invalid access */
    if (curr < 0 || curr >= EBPH_NUM_SYSCALLS)
    {
        /* #ifdef EBPH_DEBUG */
        /* bpf_trace_printk("ebpH_lookahead: Invalid curr value %ld\n", curr); */
        /* #endif */
        return 0;
    }

    /* Invalid access */
    if (prev < 0 || prev >= EBPH_NUM_SYSCALLS)
    {
        /* #ifdef EBPH_DEBUG */
        /* bpf_trace_printk("ebpH_lookahead: Invalid prev value %ld\n", prev); */
        /* #endif */
        return 0;
    }

    return curr * EBPH_NUM_SYSCALLS + prev;
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

    if (process->seq.top == EBPH_SEQSTACK_SIZE - 1)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_push_seq: Cannot push to stack since top is %d\n", process->seq.top);
        #endif
        return -2;
    }

    /* Increment top if we can */
    process->seq.top++;

    /* Reinitialize the sequence */
    for (int i = 0; i < EBPH_SEQLEN; i++)
    {
        int seq_index = i + ebpH_seq_index(process);
        if (seq_index >= 0 && seq_index < EBPH_SEQLEN * EBPH_SEQSTACK_SIZE)
            process->seq.seq[i] = EBPH_EMPTY;
    }

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
    if (process->seq.top == 0)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_pop_seq: Cannot pop from stack, top is %d\n", process->seq.top);
        #endif
        return -2;
    }

    /* Decrement top */
    process->seq.top--;

    return 0;
}

static int ebpH_seq_index(struct ebpH_process *process)
{
    /* Check to see if process is null */
    if (!process)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_seq_index: Null process\n");
        #endif
        return 0;
    }

    return (process->seq.top * EBPH_SEQLEN) % (EBPH_SEQLEN * EBPH_SEQSTACK_SIZE);
}

static int ebpH_process_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    int anomalies = 0;

    if (profile->normal)
    {
        anomalies = ebpH_test(&(profile->test), process, ctx);
        if (anomalies)
        {
            on_anomaly.perf_submit(ctx, process, sizeof(*process));
            // TODO: check for successful submission here

            if (profile->anomalies > EBPH_ANOMALY_LIMIT)
            {
                ebpH_stop_normal(profile, process, ctx);
                on_anomaly_limit.perf_submit(ctx, process, sizeof(*process));
            }
        }
    }

out:
    ebpH_add_anomaly_count(profile, process, anomalies, ctx);

    return 0;
}

static int ebpH_test(struct ebpH_profile_data *data, struct ebpH_process *process, struct pt_regs *ctx)
{
    int mismatches = 0;

    if (!process)
    {
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_test: Null process\n");
        #endif
        return 0;
    }

    for (int i = 1; i < EBPH_SEQLEN; i++)
    {
        int seq_index = i + ebpH_seq_index(process);
        if (seq_index >= 0 && seq_index < EBPH_SEQLEN * EBPH_SEQSTACK_SIZE)
        {
            u32 curr = process->seq.seq[0];
            u32 prev = process->seq.seq[i];

            u32 lookahead_index = ebpH_lookahead_index(data, curr, prev);

            if (prev == EBPH_EMPTY)
            {
                break;
            }

            if (lookahead_index >= 0 && lookahead_index < EBPH_NUM_SYSCALLS * EBPH_NUM_SYSCALLS)
            {
                /* check for mismatch */
                if ((data->flags[lookahead_index] & (1 << (i-1))) == 0)
                {
                    mismatches++;
                }
            }
            else
            {
                // FIXME: error logging causes back edge here, figure out why
                /* #ifdef EBPH_DEBUG */
                /* bpf_trace_printk("ebpH_add_seq: Null entry at (curr, prev) = (%ld, %ld)\n", curr, prev); */
                /* #endif */
            }
        }
    }

    return mismatches;
}

static int ebpH_train(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    /* This has to be BEFORE the following exclusive add instruction */
    int mismatches = ebpH_test(&(profile->train), process, ctx);

    /* update train_count and last_mod_count */
    lock_xadd(&profile->train.train_count, 1);

    if (mismatches)
    {
        if (profile->frozen)
        {
            profile->frozen = 0;
        }
        ebpH_add_seq(profile, process, ctx);
        lock_xadd(&profile->train.sequences, 1);
        profile->train.last_mod_count = 0;

        /* Log new sequence if configured to do so */
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
        {
            return 0;
        }

        u64 normal_count = profile->train.train_count - profile->train.last_mod_count;

        if ((normal_count > 0) && (profile->train.train_count * EBPH_NORMAL_FACTOR_DEN >
                    normal_count * EBPH_NORMAL_FACTOR))
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

    if (process)
    {
        ebpH_reset_ALF(process, ctx);
        on_start_normal.perf_submit(ctx, process, sizeof(*process));
    }
    else
    {
        on_start_normal.perf_submit(ctx, profile, sizeof(*profile));
    }

    return 0;
}

static int ebpH_stop_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx)
{
    profile->normal = 0;

    if (process)
    {
        ebpH_reset_ALF(process, ctx);
    }

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

    for (int i = 1; i < EBPH_SEQLEN; i++)
    {
        int seq_index = i + ebpH_seq_index(process);
        if (seq_index >= 0 && seq_index < EBPH_SEQLEN * EBPH_SEQSTACK_SIZE)
        {
            u32 curr = process->seq.seq[0];
            u32 prev = process->seq.seq[i];

            if (prev == EBPH_EMPTY)
                break;

            u32 lookahead_index = ebpH_lookahead_index(&profile->train, curr, prev);
            if (lookahead_index >= 0 && lookahead_index < EBPH_NUM_SYSCALLS * EBPH_NUM_SYSCALLS)
            {
                profile->train.flags[lookahead_index] |= (1 << (i - 1));
            }
            else
            {
                #ifdef EBPH_DEBUG
                bpf_trace_printk("ebpH_add_seq: Null entry at (curr, prev) = (%ld, %ld)\n", curr, prev);
                #endif
            }
        }
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

static int ebpH_process_syscall(struct ebpH_process *process, u32 *syscall, struct pt_regs *ctx)
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

    stats_increment(STATS_SYSCALLS);

    profile = profiles.lookup(&(process->profile_key));

    if (!profile)
    {
        EBPH_ERROR("ebpH_process_syscall: Null profile", ctx);
        #ifdef EBPH_DEBUG
        bpf_trace_printk("ebpH_process_syscall: Null profile for key %llu\n", process->profile_key);
        #endif
        return -1;
    }

    lock_xadd(&profile->count, 1);

    for (int i = EBPH_SEQLEN - 1; i > 0; i--)
    {
        int seq_index = i + ebpH_seq_index(process);
        if (seq_index >= 1 && seq_index < EBPH_SEQLEN * EBPH_SEQSTACK_SIZE)
            process->seq.seq[i] = process->seq.seq[i-1];
    }
    process->seq.seq[0] = *syscall;

    /* TODO: take profile lock here */

    ebpH_train(profile, process, ctx);

    /* Update normal status if we are frozen and have reached normal_time */
    if (ebpH_check_normal_time(profile, ctx) && !profile->normal)
    {
        ebpH_start_normal(profile, process, ctx);
    }

    ebpH_process_normal(profile, process, ctx);

    lfc = process->alf.total;
    if (lfc > EBPH_TOLERIZE_LIMIT)
    {
        ebpH_reset_profile_data(&(profile->train), ctx);
        profile->anomalies = 0;
        on_tolerize_limit.perf_submit(ctx, process, sizeof(*process));
    }

    /* TODO: release profile lock here */

    /* TODO: delay task here */

    return 0;
}

/* Create a process struct for the given pid if it doesn't exist */
static int ebpH_create_process(u32 *pid, struct task_struct *task, struct pt_regs *ctx)
{
    int zero = 0;
    struct ebpH_process *process;

    /* Process already exists */
    if (processes.lookup(pid))
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
    process = processes.lookup_or_try_init(pid, process);
    if (!process)
    {
        EBPH_ERROR("ebpH_create_process: Unable to add process to map", ctx);
        return -1;
    }

    /* User pid and tid (kernel tgid and pid respectively) */
    process->pid = task->tgid;
    process->tid = task->pid;

    /* Reset process' sequence stack */
    for (int i = 0; i < EBPH_SEQLEN * EBPH_SEQSTACK_SIZE; i++)
    {
        process->seq.seq[i] = EBPH_EMPTY;
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
        return -1;
    }

    process->profile_key = profile->key;

    return 0;
}

/* Create a profile if one does not already exist. */
static int ebpH_create_profile(u64 *key, const char *comm, struct pt_regs *ctx)
{
    int zero = 0;
    struct ebpH_profile *profile = NULL;

    if (!key)
    {
        EBPH_ERROR("ebpH_create_profile: Null key", ctx);
        return -1;
    }

    if (!comm)
    {
        EBPH_ERROR("ebpH_create_profile: Null comm", ctx);
        return -1;
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
        return -1;
    }

    /* Copy memory over */
    profile = profiles.lookup_or_try_init(key, profile);
    if (!profile)
    {
        EBPH_ERROR("ebpH_create_profile: Unable to add profile to map", ctx);
        #ifdef EBPH_DEBUG
        bpf_trace_printk("Unable to add profile to map, pid=%lu, comm=%s, key=%llu\n", ebpH_get_pid(), comm, *key);
        #endif
        return -1;
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
    bpf_probe_read(data->flags, sizeof(data->flags), &zero);

    data->last_mod_count = 0;
    data->train_count = 0;
    data->sequences = 0;

    return 0;
}

static int ebpH_reset_profile(struct ebpH_profile *profile, struct pt_regs *ctx)
{
    ebpH_reset_profile_data(&profile->train, ctx);
    ebpH_reset_profile_data(&profile->test, ctx);

    profile->anomalies = 0;
    profile->normal = 0;
    profile->frozen = 0;
    profile->normal_time = 0;
    profile->count = 0;

    ebpH_set_normal_time(profile, ctx);

    return 0;
}

/* Tracepoints and kprobes below this line --------------------- */

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
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

    if (args->id < 0)
    {
        return 0;
    }

    u32 syscall = args->id;
    u32 pid = ebpH_get_pid();

    process = processes.lookup(&pid);

    /* Process does not already exist */
    if (!process)
    {
        return 0;
    }

    /* Pop if we are flagged for popping
     * See below */
    if (process->seq.should_pop)
    {
        process->seq.should_pop = 0;
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
        process = processes.lookup(&pid);
        if (!process)
        {
            return 0;
        }

        process->seq.should_pop = 1;
    }

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    struct ebpH_profile *profile;
    struct ebpH_process *process;

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

    if (args->id < 0)
    {
        return 0;
    }

    u32 syscall = args->id;
    u32 pid = ebpH_get_pid();

    process = processes.lookup(&pid);
    if (!process)
    {
        return 0;
    }

    profile = profiles.lookup(&process->profile_key);
    if (!profile)
    {
        return 0;
    }

    /* Process syscall if it won't be restarted */
    if (args->ret != -ERESTARTSYS && args->ret != -ERESTARTNOHAND
            && args->ret != -ERESTARTNOINTR && args->ret != -ERESTART_RESTARTBLOCK)
    {
        ebpH_process_syscall(process, &syscall, (struct pt_regs *)args);
    }

    return 0;
}

RAW_TRACEPOINT_PROBE(sched_process_fork)
{
    struct ebpH_process *process;
    struct ebpH_process *parent_process;
    struct ebpH_profile *profile;

    struct task_struct *p = (struct task_struct *)ctx->args[0];
    struct task_struct *c = (struct task_struct *)ctx->args[1];

    u32 ppid = p->pid;
    u32 cpid = c->pid;

    /* Create the process */
    ebpH_create_process(&cpid, c, (struct pt_regs *)ctx);
    process = processes.lookup(&cpid);
    if (!process)
    {
        EBPH_ERROR("sched:sched_process_fork: Unable to lookup process after creation", (struct pt_regs *)ctx);
        return -1;
    }

    /* Attemp to look up parent process */
    parent_process = processes.lookup(&ppid);
    if (!parent_process)
    {
        return 0;
    }

    /* Reset process' sequence stack */
    for (int i = 0; i < EBPH_SEQLEN * EBPH_SEQSTACK_SIZE; i++)
    {
        process->seq.seq[i] = parent_process->seq.seq[i];
    }

    /* Attempt to look up parent profile */
    profile = profiles.lookup(&parent_process->profile_key);
    if (!profile)
    {
        return 0;
    }

    /* Start tracing the process */
    ebpH_start_tracing(profile, process, (struct pt_regs *)ctx);

    return 0;
}

RAW_TRACEPOINT_PROBE(sched_process_exec)
{
    u32 pid = ebpH_get_pid();

    /* Look up process */
    struct ebpH_process *process = processes.lookup(&pid);
    if (!process)
    {
        return 0;
    }

    /* Yoink the linux_binprm */
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    /* Calculate profile_key
     * Take inode number and filesystem device number together */
    u64 profile_key = (u64)bprm->file->f_path.dentry->d_inode->i_ino | ((u64)new_encode_dev(bprm->file->f_path.dentry->d_inode->i_sb->s_dev) << 32);

    /* Create profile if necessary */
    ebpH_create_profile(&profile_key, bprm->file->f_path.dentry->d_name.name, (struct pt_regs *)ctx);

    /* Look up profile */
    struct ebpH_profile *profile = profiles.lookup(&profile_key);
    if (!profile)
    {
        EBPH_ERROR("sched_process_exec: Unable to lookup profile", (struct pt_regs *)ctx);
        return 0;
    }

    /* Reset process' sequence stack */
    for (int i = 0; i < EBPH_SEQLEN * EBPH_SEQSTACK_SIZE; i++)
    {
        process->seq.seq[i] = EBPH_EMPTY;
    }

    /* Start tracing the process */
    ebpH_start_tracing(profile, process, (struct pt_regs *)ctx);

    return 0;
}

/* When a task exits */
RAW_TRACEPOINT_PROBE(sched_process_exit)
{
    u32 pid = ebpH_get_pid();
    processes.delete(&pid);

    return 0;
}

/* Entry hook for kernel signal handler implementation */
int kretprobe__get_signal(struct pt_regs *ctx)
{
    /* Nothing to handle */
    if (!PT_REGS_RC(ctx))
    {
        return 0;
    }

    u32 pid = ebpH_get_pid();

    struct ebpH_process *process = processes.lookup(&pid);
    if (!process)
    {
        /* Process is not being traced */
        return 0;
    }

    if (ebpH_push_seq(process))
    {
        EBPH_ERROR("kretprobe__get_signal: Failed to push sequence onto stack", ctx);
        return -1;
    }

    return 0;
}

/* Normalize process command */
int cmd_normalize_process(struct pt_regs *ctx)
{
    u32 pid = (u32)PT_REGS_PARM1(ctx);

    struct ebpH_process *process = processes.lookup(&pid);
    if (!process)
    {
        EBPH_ERROR("cmd_normalize_process: No such process", ctx);
        return -1;
    }

    struct ebpH_profile *profile = profiles.lookup(&process->profile_key);
    if (!profile)
    {
        EBPH_ERROR("cmd_normalize_process: No such profile", ctx);
        return -2;
    }

    ebpH_start_normal(profile, process, ctx);

    return 0;
}

/* Tolerize process process command */
int cmd_tolerize_process(struct pt_regs *ctx)
{
    u32 pid = (u32)PT_REGS_PARM1(ctx);

    struct ebpH_process *process = processes.lookup(&pid);
    if (!process)
    {
        EBPH_ERROR("cmd_tolerize_process: No such process", ctx);
        return -1;
    }

    struct ebpH_profile *profile = profiles.lookup(&process->profile_key);
    if (!profile)
    {
        EBPH_ERROR("cmd_tolerize_process: No such profile", ctx);
        return -2;
    }

    // TODO: implement

    return 0;
}

/* Normalize profile command */
int cmd_normalize_profile(struct pt_regs *ctx)
{
    u64 key = (u64)PT_REGS_PARM1(ctx);

    struct ebpH_profile *profile = profiles.lookup(&key);
    if (!profile)
    {
        EBPH_ERROR("cmd_normalize_profile: No such profile", ctx);
        return -2;
    }

    ebpH_start_normal(profile, NULL, ctx);

    return 0;
}

/* Tolerize profile profile command */
int cmd_tolerize_profile(struct pt_regs *ctx)
{
    u64 key = (u64)PT_REGS_PARM1(ctx);

    struct ebpH_profile *profile = profiles.lookup(&key);
    if (!profile)
    {
        EBPH_ERROR("cmd_tolerize_profile: No such profile", ctx);
        return -2;
    }

    // TODO: implement

    return 0;
}

/* Reset command */
int cmd_reset_profile(struct pt_regs *ctx)
{
    u64 key = (u64)PT_REGS_PARM1(ctx);

    struct ebpH_profile *profile = profiles.lookup(&key);
    if (!profile)
    {
        EBPH_ERROR("cmd_reset_profile: No such profile", ctx);
        return -2;
    }

    return ebpH_reset_profile(profile, ctx);
}
