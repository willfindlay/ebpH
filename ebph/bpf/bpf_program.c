#include "bpf_program.h"

/* =========================================================================
 * Maps
 * ========================================================================= */

/* PID (Kernel) -> Task State */
BPF_HASH(task_states, u32, struct ebph_task_state_t, EBPH_MAX_PROCESSES);

/* Profile Key -> Profile */
BPF_HASH(profiles, u64, struct ebph_profile_t, EBPH_MAX_PROFILES);

/* {Profile Key, Curr Syscall} -> {Prev Syscall Flags} */
BPF_F_TABLE("hash", struct ebph_flags_key_t, struct ebph_flags_t, training_data,
            (EBPH_MAX_PROFILES * EBPH_NUM_SYSCALLS), BPF_F_NO_PREALLOC);

/* {Profile Key, Curr Syscall} -> {Prev Syscall Flags} */
BPF_F_TABLE("hash", struct ebph_flags_key_t, struct ebph_flags_t, testing_data,
            (EBPH_MAX_PROFILES * EBPH_NUM_SYSCALLS), BPF_F_NO_PREALLOC);

/* {PID (Kernel), Stack Top} -> Sequence Stack */
BPF_F_TABLE("hash", struct ebph_sequence_key_t, struct ebph_sequence_t,
            sequences, (EBPH_MAX_PROCESSES * EBPH_SEQSTACK_FRAMES),
            BPF_F_NO_PREALLOC);

/* The following arrays are read-only, used for initializing large data. */
BPF_ARRAY(_init_flags, struct ebph_flags_t, 1);
static __always_inline struct ebph_flags_t *ebph_new_flags()
{
    int zero = 0;
    return _init_flags.lookup(&zero);
}

/* =========================================================================
 * Ring Buffers
 * ========================================================================= */

struct ebph_new_profile_event_t {
    u64 profile_key;
    char pathname[PATH_MAX];
};

BPF_RINGBUF_OUTPUT(new_profile_events, 8);

static __always_inline void ebph_log_new_profile(u64 profile_key,
                                                 struct dentry *dentry)
{
    struct ebph_new_profile_event_t *event = new_profile_events.ringbuf_reserve(
        sizeof(struct ebph_new_profile_event_t));
    if (event) {
        // TODO: change this to bpf_d_path when it comes out (Linux 5.9?)
        bpf_get_current_comm(event->pathname, sizeof(event->pathname));
        event->profile_key = profile_key;
        new_profile_events.ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
    }
}

struct ebph_anomaly_event_t {
    u16 syscall;
    int misses;
    u32 pid;
    u64 profile_key;
    u64 task_count;
};

BPF_RINGBUF_OUTPUT(anomaly_events, 8);

static __always_inline void ebph_log_anomaly(u16 syscall, int misses,
                                             struct ebph_task_state_t *s)
{
    struct ebph_anomaly_event_t *event =
        anomaly_events.ringbuf_reserve(sizeof(struct ebph_anomaly_event_t));
    if (event) {
        event->syscall     = syscall;
        event->misses      = misses;
        event->pid         = s->pid;
        event->profile_key = s->profile_key;
        event->task_count  = s->count;
        anomaly_events.ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
    }
}

struct ebph_start_normal_event_t {
    u32 pid;
    u64 profile_key;
    u64 profile_count;
    u64 task_count;
    u64 sequences;
    u64 train_count;
    u64 last_mod_count;
    u8 in_task;
};

BPF_RINGBUF_OUTPUT(start_normal_events, 8);

static __always_inline void ebph_log_start_normal(u64 profile_key,
                                                  struct ebph_task_state_t *s,
                                                  struct ebph_profile_t *p)
{
    struct ebph_start_normal_event_t *event =
        start_normal_events.ringbuf_reserve(
            sizeof(struct ebph_start_normal_event_t));
    if (event) {
        if (s) {
            event->pid        = s->pid;
            event->task_count = s->count;
            event->in_task    = 1;
        } else {
            event->in_task = 0;
        }
        event->profile_key    = profile_key;
        event->profile_count  = p->count;
        event->train_count    = p->train_count;
        event->last_mod_count = p->last_mod_count;
        event->sequences      = p->sequences;
        start_normal_events.ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
    }
}

struct ebph_stop_normal_event_t {
    u32 pid;
    u64 profile_key;
    u64 task_count;
    u64 anomalies;
    u64 anomaly_limit;
    u8 in_task;
};

BPF_RINGBUF_OUTPUT(stop_normal_events, 8);

static __always_inline void ebph_log_stop_normal(u64 profile_key,
                                                 struct ebph_task_state_t *s,
                                                 struct ebph_profile_t *p)
{
    struct ebph_stop_normal_event_t *event = stop_normal_events.ringbuf_reserve(
        sizeof(struct ebph_stop_normal_event_t));
    if (event) {
        if (s) {
            event->pid        = s->pid;
            event->task_count = s->count;
            event->in_task    = 1;
        } else {
            event->in_task = 0;
        }
        event->profile_key   = profile_key;
        event->anomalies     = p->anomaly_count;
        event->anomaly_limit = EBPH_ANOMALY_LIMIT;
        stop_normal_events.ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
    }
}

#ifdef EBPH_DEBUG
struct ebph_new_task_state_event_t {
    u32 pid;
    u64 profile_key;
};

BPF_RINGBUF_OUTPUT(new_task_state_events, 8);

static __always_inline void ebph_log_new_task_state(u32 pid, u64 profile_key)
{
    struct ebph_new_task_state_event_t *event =
        new_task_state_events.ringbuf_reserve(
            sizeof(struct ebph_new_task_state_event_t));
    if (event) {
        event->pid         = pid;
        event->profile_key = profile_key;
        new_task_state_events.ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
    }
}
#else
static __always_inline void ebph_log_new_task_state(u32 pid, u64 profile_key)
{
    // NOP
}
#endif

/* =========================================================================
 * BPF Programs
 * ========================================================================= */

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    if (args->id < 0) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid();

    struct ebph_task_state_t *task_state = task_states.lookup(&pid);
    if (!task_state) {
        return 0;
    }

    if (args->id == EBPH_SYS_RT_SIGRETURN) {
        if (!ebph_pop_seq(task_state)) {
            // TODO: log warning
        }
    }

    ebph_handle_syscall(task_state, (u16)args->id);

    return 0;
}

RAW_TRACEPOINT_PROBE(sched_process_fork)
{
    struct ebph_task_state_t *parent_state;
    struct ebph_task_state_t *child_state;

    struct task_struct *p = (struct task_struct *)ctx->args[0];
    struct task_struct *c = (struct task_struct *)ctx->args[1];

    u32 ppid = p->pid;

    // Look up parent task state if it exists
    parent_state = task_states.lookup(&ppid);
    if (!parent_state) {
        return 0;
    }

    u32 cpid  = c->pid;
    u32 ctgid = c->tgid;

    u8 task_state_exists = task_states.lookup(&cpid) ? 1 : 0;

    child_state = ebph_new_task_state(cpid, ctgid, parent_state->profile_key);
    if (!child_state) {
        // TODO: log error
        return 1;
    }

    if (!task_state_exists) {
        ebph_log_new_task_state(cpid, parent_state->profile_key);
    }

    return 0;
}

RAW_TRACEPOINT_PROBE(sched_process_exec)
{
    /* Yoink the linux_binprm */
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    /* Calculate profile_key by taking inode number and filesystem device
     * number together */
    u64 profile_key =
        (u64)bprm->file->f_path.dentry->d_inode->i_ino |
        ((u64)new_encode_dev(bprm->file->f_path.dentry->d_inode->i_sb->s_dev)
         << 32);

    u32 pid  = bpf_get_current_pid_tgid();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    u8 task_state_exists = task_states.lookup(&pid) ? 1 : 0;

    /* Create or look up task_state. */
    struct ebph_task_state_t *task_state =
        ebph_new_task_state(pid, tgid, profile_key);
    if (!task_state) {
        // TODO: log error
        return 1;
    }

    if (!task_state_exists) {
        ebph_log_new_task_state(pid, profile_key);
    }

    // TODO: reset ALF

    // Does the profile already exist? Important for logging purposes
    u8 profile_exists = profiles.lookup(&profile_key) ? 1 : 0;

    struct ebph_profile_t *profile = ebph_new_profile(profile_key);
    if (!profile) {
        // TODO: log error
        return 1;
    }

    if (!profile_exists) {
        ebph_log_new_profile(profile_key, bprm->file->f_path.dentry);
    }

    // Reset sequence stack
    task_state->seqstack_top    = 0;
    struct ebph_sequence_t *seq = ebph_peek_seq(task_state);
    if (!seq) {
        // TODO: log error
        return 1;
    }
    for (int i = 0; i < EBPH_SEQLEN; i++) {
        seq->calls[i] = EBPH_EMPTY;
    }

    task_state->profile_key = profile_key;

    return 0;
}

/* When a task exits */
RAW_TRACEPOINT_PROBE(sched_process_exit)
{
    u32 pid = bpf_get_current_pid_tgid();
    task_states.delete(&pid);

    struct ebph_sequence_key_t key = {};

    key.pid = pid;

    for (int i = 0; i < EBPH_SEQSTACK_FRAMES; i++) {
        key.seqstack_top = i;
        sequences.delete(&key);
    }

    return 0;
}

TRACEPOINT_PROBE(signal, signal_deliver)
{
    u32 pid = bpf_get_current_pid_tgid();

    struct ebph_task_state_t *task_state = task_states.lookup(&pid);
    if (!task_state) {
        return 0;
    }

    // Signal is ignored or not handled
    if (args->sa_handler == (long)SIG_IGN ||
        args->sa_handler == (long)SIG_DFL) {
        return 0;
    }

    // Push a new sequence
    if (!ebph_push_seq(task_state)) {
        // TODO log warning
    }

    return 0;
}

/* =========================================================================
 * Helper Functions
 * ========================================================================= */

/* Calculate current epoch time in nanoseconds. */
static __always_inline u64 ebph_current_time()
{
    return (u64)bpf_ktime_get_ns() + EBPH_BOOT_EPOCH;
};

/* Look up and return a copy of training data for profile @profile_key
 * at position {@curr, @prev}. */
static __always_inline u8 ebph_get_training_data(u64 profile_key, u16 curr,
                                                 u16 prev)
{
    curr &= EBPH_NUM_SYSCALLS - 1;
    prev &= EBPH_NUM_SYSCALLS - 1;

    struct ebph_flags_t *flags = ebph_new_flags();
    if (!flags) {
        // TODO log error
        return 0;
    }

    struct ebph_flags_key_t key = {};

    key.profile_key = profile_key;
    key.curr        = curr;

    flags = training_data.lookup_or_init(&key, flags);
    if (!flags) {
        // TODO log error
        return 0;
    }

    return flags->prev[prev];
}

/* Look up and return a copy of testing data for profile @profile_key
 * at position {@curr, @prev}. */
static __always_inline u8 ebph_get_testing_data(u64 profile_key, u16 curr,
                                                u16 prev)
{
    curr &= EBPH_NUM_SYSCALLS - 1;
    prev &= EBPH_NUM_SYSCALLS - 1;

    struct ebph_flags_t *flags = ebph_new_flags();
    if (!flags) {
        // TODO log error
        return 0;
    }

    struct ebph_flags_key_t key = {};

    key.profile_key = profile_key;
    key.curr        = curr;

    flags = testing_data.lookup_or_init(&key, flags);
    if (!flags) {
        // TODO log error
        return 0;
    }

    return flags->prev[prev];
}

static __always_inline int ebph_set_training_data(u64 profile_key, u16 curr,
                                                  u16 prev, u8 new_flag)
{
    curr &= EBPH_NUM_SYSCALLS - 1;
    prev &= EBPH_NUM_SYSCALLS - 1;

    struct ebph_flags_t *flags = ebph_new_flags();
    if (!flags) {
        // TODO log error
        return 0;
    }

    struct ebph_flags_key_t key = {};

    key.profile_key = profile_key;
    key.curr        = curr;

    flags = training_data.lookup_or_init(&key, flags);
    if (!flags) {
        // TODO log error
        return 0;
    }

    flags->prev[prev] = new_flag;

    return 0;
}

static __always_inline int ebph_set_testing_data(u64 profile_key, u16 curr,
                                                 u16 prev, u8 new_flag)
{
    curr &= EBPH_NUM_SYSCALLS - 1;
    prev &= EBPH_NUM_SYSCALLS - 1;

    struct ebph_flags_t *flags = ebph_new_flags();
    if (!flags) {
        // TODO log error
        return 0;
    }

    struct ebph_flags_key_t key = {};

    key.profile_key = profile_key;
    key.curr        = curr;

    flags = testing_data.lookup_or_init(&key, flags);
    if (!flags) {
        // TODO log error
        return 0;
    }

    flags->prev[prev] = new_flag;

    return 0;
}

/* Create a new task_state {@pid, @tgid, @profile_key} at @pid. */
static __always_inline struct ebph_task_state_t *ebph_new_task_state(
    u32 pid, u32 tgid, u64 profile_key)
{
    struct ebph_task_state_t task_state = {};

    task_state.pid          = pid;
    task_state.tgid         = tgid;
    task_state.profile_key  = profile_key;
    task_state.count        = 0;
    task_state.seqstack_top = -1;

    if (!ebph_push_seq(&task_state)) {
        // TODO log error
        return NULL;
    }

    return task_states.lookup_or_try_init(&pid, &task_state);
}

/* Calculate normal time for a new profile. */
static __always_inline void ebph_set_normal_time(struct ebph_profile_t *profile)
{
    profile->normal_time = ebph_current_time() + EBPH_NORMAL_WAIT;
};

/* Create a new profile at @profile_key. */
static __always_inline struct ebph_profile_t *ebph_new_profile(u64 profile_key)
{
    struct ebph_profile_t profile = {};

    profile.status         = EBPH_PROFILE_STATUS_TRAINING;
    profile.train_count    = 0;
    profile.last_mod_count = 0;
    profile.sequences      = 0;
    profile.anomaly_count  = 0;
    profile.count          = 0;

    ebph_set_normal_time(&profile);

    return profiles.lookup_or_try_init(&profile_key, &profile);
}

/* Push a new frame onto the sequence stack for @task_state. */
static __always_inline struct ebph_sequence_t *ebph_push_seq(
    struct ebph_task_state_t *task_state)
{
    // Stack is full
    if (task_state->seqstack_top + 1 >= EBPH_SEQSTACK_FRAMES) {
        // TODO: log warning
        return NULL;
    }

    // Increment top of stack
    task_state->seqstack_top++;

    struct ebph_sequence_key_t key = {};

    // Set key
    key.pid          = task_state->pid;
    key.seqstack_top = task_state->seqstack_top;

    struct ebph_sequence_t new_seq = {};

    // Initialize sequence
    for (int i = 0; i < EBPH_SEQLEN; i++) {
        new_seq.calls[i] = EBPH_EMPTY;
    }

    sequences.update(&key, &new_seq);

    return sequences.lookup(&key);
}

/* Pop a frame from the sequence stack for @task_state. */
static __always_inline struct ebph_sequence_t *ebph_pop_seq(
    struct ebph_task_state_t *task_state)
{
    // Stack would be empty
    if (task_state->seqstack_top == 0) {
        // TODO: log warning
        return NULL;
    }

    struct ebph_sequence_key_t key = {};

    // Set key
    key.pid          = task_state->pid;
    key.seqstack_top = task_state->seqstack_top;

    // Decrement top of stack
    task_state->seqstack_top--;

    return sequences.lookup(&key);
}

/* Peek a frame from the sequence stack for @task_state. */
static __always_inline struct ebph_sequence_t *ebph_peek_seq(
    struct ebph_task_state_t *task_state)
{
    struct ebph_sequence_key_t key = {};

    // Set key
    key.pid          = task_state->pid;
    key.seqstack_top = task_state->seqstack_top;

    return sequences.lookup(&key);
}

static __always_inline int ebph_test(struct ebph_task_state_t *task_state,
                                     struct ebph_sequence_t *sequence,
                                     bool use_testing_data)
{
    int mismatches = 0;

    for (int i = 1; i < EBPH_SEQLEN; i++) {
        u16 curr = sequence->calls[0];
        u16 prev = sequence->calls[i];

        if (curr == EBPH_EMPTY || prev == EBPH_EMPTY) {
            break;
        }

        u8 flags =
            use_testing_data
                ? ebph_get_testing_data(task_state->profile_key, curr, prev)
                : ebph_get_training_data(task_state->profile_key, curr, prev);
        if ((flags & (1 << (i - 1))) == 0) {
            mismatches++;
        }
    }

    return mismatches;
}

static __always_inline void ebph_update_training_data(
    struct ebph_task_state_t *task_state, struct ebph_sequence_t *sequence)
{
    for (int i = 1; i < EBPH_SEQLEN; i++) {
        u16 curr = sequence->calls[0];
        u16 prev = sequence->calls[i];

        if (curr == EBPH_EMPTY || prev == EBPH_EMPTY) {
            break;
        }

        u8 flags = ebph_get_training_data(task_state->profile_key, curr, prev);
        flags |= (1 << (i - 1));
        ebph_set_training_data(task_state->profile_key, curr, prev, flags);
    }
}

static __always_inline void ebph_do_train(struct ebph_task_state_t *task_state,
                                          struct ebph_profile_t *profile,
                                          struct ebph_sequence_t *sequence)
{
    int mismatches = ebph_test(task_state, sequence, false);

    lock_xadd(&profile->train_count, 1);

    if (mismatches) {
        lock_xadd(&profile->sequences, 1);
        profile->last_mod_count = 0;

        // Unfreeze profile
        profile->status &= ~EBPH_PROFILE_STATUS_FROZEN;

        ebph_update_training_data(task_state, sequence);

        // TODO
        // Log new sequence
    } else {
        lock_xadd(&profile->last_mod_count, 1);

        if (profile->status & EBPH_PROFILE_STATUS_FROZEN) {
            return;
        }

        u64 normal_count = 0;
        if (profile->train_count > profile->last_mod_count) {
            normal_count = profile->train_count - profile->last_mod_count;
        }

        if ((normal_count > 0) &&
            (profile->train_count * EBPH_NORMAL_FACTOR_DEN >
             normal_count * EBPH_NORMAL_FACTOR)) {
            // Freeze profile
            profile->status |= EBPH_PROFILE_STATUS_FROZEN;
            ebph_set_normal_time(profile);
        }
    }
}

static __always_inline void ebph_add_anomaly_count(
    struct ebph_task_state_t *task_state, struct ebph_profile_t *profile,
    int count)
{
    // TODO locality frame stuff

    if (count > 0) {
        lock_xadd(&profile->anomaly_count, 1);
        // TODO more locality frame stuff
    } else {
        // TODO more locality frame stuff
    }
}

static __always_inline void ebph_copy_train_to_test(
    struct ebph_task_state_t *task_state, struct ebph_profile_t *profile)
{
    struct ebph_flags_key_t key = {};

    key.profile_key = task_state->profile_key;

    for (u16 curr = 0; curr < EBPH_NUM_SYSCALLS; curr++) {
        key.curr = curr;
        if (!training_data.lookup(&key)) {
            continue;
        }

        struct ebph_flags_t *training_flags = training_data.lookup(&key);
        if (!training_flags) {
            continue;
        }
        testing_data.update(&key, training_flags);
    }
}

static __always_inline void ebph_start_normal(
    struct ebph_task_state_t *task_state, struct ebph_profile_t *profile)
{
    ebph_copy_train_to_test(task_state, profile);

    ebph_log_start_normal(task_state->profile_key, task_state, profile);

    profile->status         = EBPH_PROFILE_STATUS_NORMAL;
    profile->anomaly_count  = 0;
    profile->last_mod_count = 0;
    profile->train_count    = 0;
}

static __always_inline void ebph_stop_normal(
    struct ebph_task_state_t *task_state, struct ebph_profile_t *profile)
{
    ebph_log_stop_normal(task_state->profile_key, task_state, profile);

    profile->status = EBPH_PROFILE_STATUS_TRAINING;

    // TODO reset ALF here
}

static __always_inline void ebph_do_normal(struct ebph_task_state_t *task_state,
                                           struct ebph_profile_t *profile,
                                           struct ebph_sequence_t *sequence)
{
    if (!(profile->status & EBPH_PROFILE_STATUS_NORMAL)) {
        return;
    }

    int anomalies = ebph_test(task_state, sequence, true);

    if (anomalies) {
        ebph_log_anomaly(sequence->calls[0], anomalies, task_state);

        if (profile->anomaly_count > EBPH_ANOMALY_LIMIT) {
            ebph_stop_normal(task_state, profile);
        }
    }

    ebph_add_anomaly_count(task_state, profile, anomalies);
}

/* Process a new syscall. */
static __always_inline void ebph_handle_syscall(
    struct ebph_task_state_t *task_state, u16 syscall)
{
    // Look up profile
    struct ebph_profile_t *profile = profiles.lookup(&task_state->profile_key);
    if (!profile) {
        // TODO log error
        return;
    }

    // Look up current sequence
    struct ebph_sequence_t *sequence = ebph_peek_seq(task_state);
    if (!sequence) {
        // TODO log error
        return;
    }

    lock_xadd(&profile->count, 1);
    lock_xadd(&task_state->count, 1);

    // Insert syscall into sequence
    for (int i = EBPH_SEQLEN - 1; i > 0; i--) {
        sequence->calls[i] = sequence->calls[i - 1];
    }
    sequence->calls[0] = syscall;

    ebph_do_train(task_state, profile, sequence);

    /* Update normal status if we are frozen and have reached normal_time */
    if ((profile->status & EBPH_PROFILE_STATUS_FROZEN) &&
        !(profile->status & EBPH_PROFILE_STATUS_NORMAL) &&
        ebph_current_time() > profile->normal_time) {
        ebph_start_normal(task_state, profile);
    }

    ebph_do_normal(task_state, profile, sequence);

    // TODO
    // lfc = process->alf.total;
    // if (lfc > EBPH_TOLERIZE_LIMIT) {
    //    ebpH_reset_profile_data(&(profile->train), ctx);
    //    profile->anomalies = 0;
    //    on_tolerize_limit.perf_submit(ctx, process, sizeof(*process));
    //}
}
