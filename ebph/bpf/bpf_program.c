/*  ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
 *  Copyright (C) 2019-2020  William Findlay
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  Main BPF program logic.
 *
 *  2020-Jul-13  William Findlay  Created this.
 */

#include "bpf_program.h"

/* =========================================================================
 * ebpH Settings
 * ========================================================================= */

BPF_ARRAY(_ebph_settings, u64, EBPH_SETTING__END);

static __always_inline u64 ebph_get_setting(int key)
{
    u64 *res = _ebph_settings.lookup(&key);
    if (!res) {
        return 0;
    }

    return *res;
}

static __always_inline int ebph_set_setting(int key, u64 val)
{
    return _ebph_settings.update(&key, &val);
}

/* =========================================================================
 * Maps
 * =========================================================================
 */

/* PID (Kernel) -> Task State */
BPF_HASH(task_states, u32, struct ebph_task_state_t, EBPH_MAX_PROCESSES);

/* Profile Key -> Profile */
BPF_HASH(profiles, u64, struct ebph_profile_t, EBPH_MAX_PROFILES);

/* Profile Key -> Syscall Flags */
BPF_F_TABLE("hash", u64, struct ebph_flags_t, training_data, EBPH_MAX_PROFILES,
            BPF_F_NO_PREALLOC);

/* Profile Key -> {Syscall Flags} */
BPF_F_TABLE("hash", u64, struct ebph_flags_t, testing_data, EBPH_MAX_PROFILES,
            BPF_F_NO_PREALLOC);

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

/* Profile creation events */
struct ebph_new_profile_event_t {
    u64 profile_key;
    char pathname[PATH_MAX];
};

BPF_RINGBUF_OUTPUT(new_profile_events, 16);

static __always_inline void ebph_log_new_profile(u64 profile_key,
                                                 struct dentry *dentry)
{
    struct ebph_new_profile_event_t *event = new_profile_events.ringbuf_reserve(
        sizeof(struct ebph_new_profile_event_t));
    if (event) {
        // TODO: change this to bpf_d_path when it comes out (Linux 5.9?)
        bpf_probe_read_str(event->pathname, sizeof(event->pathname),
                           dentry->d_name.name);
        event->profile_key = profile_key;
        new_profile_events.ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
    }
}

/* Anomaly events */
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

/* New sequence events */
struct ebph_new_sequence_event_t {
    u32 pid;
    u64 profile_key;
    u64 profile_count;
    u64 task_count;
    u16 sequence[EBPH_SEQLEN];
};

BPF_RINGBUF_OUTPUT(new_sequence_events, 8);

static __always_inline void ebph_log_new_sequence(struct ebph_task_state_t *s,
                                                  struct ebph_profile_t *p,
                                                  struct ebph_sequence_t *seq)
{
    struct ebph_new_sequence_event_t *event =
        new_sequence_events.ringbuf_reserve(
            sizeof(struct ebph_new_sequence_event_t));
    if (event) {
        event->pid           = s->pid;
        event->profile_key   = s->profile_key;
        event->profile_count = p->count;
        event->task_count    = s->count;
        bpf_probe_read(event->sequence, sizeof(event->sequence), seq->calls);
        new_sequence_events.ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
    }
}

/* Start normal events */
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

/* Stop normal events */
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
        event->anomaly_limit = ebph_get_setting(EBPH_SETTING_ANOMALY_LIMIT);
        stop_normal_events.ringbuf_submit(event, BPF_RB_FORCE_WAKEUP);
    }
}

/* =========================================================================
 * BPF Programs
 * ========================================================================= */

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    bool monitoring = ebph_get_setting(EBPH_SETTING_MONITORING);
    if (!monitoring) {
        return 0;
    }

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
    bool monitoring = ebph_get_setting(EBPH_SETTING_MONITORING);
    if (!monitoring) {
        return 0;
    }

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

    child_state = ebph_new_task_state(cpid, ctgid, parent_state->profile_key);
    if (!child_state) {
        // TODO: log error
        return 1;
    }

    return 0;
}

RAW_TRACEPOINT_PROBE(sched_process_exec)
{
    bool monitoring = ebph_get_setting(EBPH_SETTING_MONITORING);
    if (!monitoring) {
        return 0;
    }

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

    /* Create or look up task_state. */
    struct ebph_task_state_t *task_state =
        ebph_new_task_state(pid, tgid, profile_key);
    if (!task_state) {
        // TODO: log error
        return 1;
    }

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

    // Reset task state count
    task_state->count = 0;

    // TODO: reset ALF

    task_state->profile_key = profile_key;

    return 0;
}

/* When a task exits */
RAW_TRACEPOINT_PROBE(sched_process_exit)
{
    bool monitoring = ebph_get_setting(EBPH_SETTING_MONITORING);
    if (!monitoring) {
        return 0;
    }

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
    bool monitoring = ebph_get_setting(EBPH_SETTING_MONITORING);
    if (!monitoring) {
        return 0;
    }

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
 * USDT Commands
 * ========================================================================= */

int command_set_setting(struct pt_regs *ctx)
{
    /* USDT arguments */
    int *rc_p;
    bpf_usdt_readarg(1, ctx, &rc_p);
    int *key_p;
    bpf_usdt_readarg(2, ctx, &key_p);
    u64 *val_p;
    bpf_usdt_readarg(3, ctx, &val_p);

    int rc = 0;

    int key;
    if (bpf_probe_read(&key, sizeof(key), key_p) < 0) {
        rc = -ENOMEM;
        goto out;
    }

    u64 val;
    if (bpf_probe_read(&val, sizeof(val), val_p) < 0) {
        rc = -ENOMEM;
        goto out;
    }

    if (ebph_get_setting(key) == val) {
        rc = 1;
        goto out;
    }

    if (ebph_set_setting(key, val)) {
        rc = -EINVAL;
        goto out;
    }

out:
    bpf_probe_write_user(rc_p, &rc, sizeof(rc));

    return 0;
}

int command_normalize_profile(struct pt_regs *ctx)
{
    /* USDT arguments */
    int *rc_p;
    bpf_usdt_readarg(1, ctx, &rc_p);
    u64 *profile_key_p;
    bpf_usdt_readarg(2, ctx, &profile_key_p);

    int rc = 0;

    u64 profile_key;
    if (bpf_probe_read(&profile_key, sizeof(profile_key), profile_key_p) < 0) {
        rc = -ENOMEM;
        goto out;
    }

    struct ebph_profile_t *profile = profiles.lookup(&profile_key);
    if (!profile) {
        rc = -ESRCH;
        goto out;
    }

    ebph_start_normal(profile_key, NULL, profile);

out:
    bpf_probe_write_user(rc_p, &rc, sizeof(rc));

    return 0;
}

int command_normalize_process(struct pt_regs *ctx)
{
    /* USDT arguments */
    int *rc_p;
    bpf_usdt_readarg(1, ctx, &rc_p);
    u32 *pid_p;
    bpf_usdt_readarg(2, ctx, &pid_p);

    int rc = 0;

    u32 pid;
    if (bpf_probe_read(&pid, sizeof(pid), pid_p) < 0) {
        rc = -ENOMEM;
        goto out;
    }

    struct ebph_task_state_t *s = task_states.lookup(&pid);
    if (!s) {
        rc = -ESRCH;
        goto out;
    }

    struct ebph_profile_t *profile = profiles.lookup(&s->profile_key);
    if (!profile) {
        rc = -ESRCH;
        goto out;
    }

    ebph_start_normal(s->profile_key, s, profile);

out:
    bpf_probe_write_user(rc_p, &rc, sizeof(rc));

    return 0;
}

int command_sensitize_profile(struct pt_regs *ctx)
{
    /* USDT arguments */
    int *rc_p;
    bpf_usdt_readarg(1, ctx, &rc_p);
    u64 *profile_key_p;
    bpf_usdt_readarg(2, ctx, &profile_key_p);

    int rc = 0;

    u64 profile_key;
    if (bpf_probe_read(&profile_key, sizeof(profile_key), profile_key_p) < 0) {
        rc = -ENOMEM;
        goto out;
    }

    struct ebph_profile_t *profile = profiles.lookup(&profile_key);
    if (!profile) {
        rc = -ESRCH;
        goto out;
    }

    ebph_reset_training_data(profile_key, NULL, profile);

out:
    bpf_probe_write_user(rc_p, &rc, sizeof(rc));

    return 0;
}

int command_sensitize_process(struct pt_regs *ctx)
{
    /* USDT arguments */
    int *rc_p;
    bpf_usdt_readarg(1, ctx, &rc_p);
    u32 *pid_p;
    bpf_usdt_readarg(2, ctx, &pid_p);

    int rc = 0;

    u32 pid;
    if (bpf_probe_read(&pid, sizeof(pid), pid_p) < 0) {
        rc = -ENOMEM;
        goto out;
    }

    struct ebph_task_state_t *s = task_states.lookup(&pid);
    if (!s) {
        rc = -ESRCH;
        goto out;
    }

    struct ebph_profile_t *profile = profiles.lookup(&s->profile_key);
    if (!profile) {
        rc = -ESRCH;
        goto out;
    }

    ebph_reset_training_data(s->profile_key, s, profile);

out:
    bpf_probe_write_user(rc_p, &rc, sizeof(rc));

    return 0;
}

int command_tolerize_profile(struct pt_regs *ctx)
{
    /* USDT arguments */
    int *rc_p;
    bpf_usdt_readarg(1, ctx, &rc_p);
    u64 *profile_key_p;
    bpf_usdt_readarg(2, ctx, &profile_key_p);

    int rc = 0;

    u64 profile_key;
    if (bpf_probe_read(&profile_key, sizeof(profile_key), profile_key_p) < 0) {
        rc = -ENOMEM;
        goto out;
    }

    struct ebph_profile_t *profile = profiles.lookup(&profile_key);
    if (!profile) {
        rc = -ESRCH;
        goto out;
    }

    ebph_stop_normal(profile_key, NULL, profile);

out:
    bpf_probe_write_user(rc_p, &rc, sizeof(rc));

    return 0;
}

int command_tolerize_process(struct pt_regs *ctx)
{
    /* USDT arguments */
    int *rc_p;
    bpf_usdt_readarg(1, ctx, &rc_p);
    u32 *pid_p;
    bpf_usdt_readarg(2, ctx, &pid_p);

    int rc = 0;

    u32 pid;
    if (bpf_probe_read(&pid, sizeof(pid), pid_p) < 0) {
        rc = -ENOMEM;
        goto out;
    }

    struct ebph_task_state_t *s = task_states.lookup(&pid);
    if (!s) {
        rc = -ESRCH;
        goto out;
    }

    struct ebph_profile_t *profile = profiles.lookup(&s->profile_key);
    if (!profile) {
        rc = -ESRCH;
        goto out;
    }

    ebph_stop_normal(s->profile_key, s, profile);

out:
    bpf_probe_write_user(rc_p, &rc, sizeof(rc));

    return 0;
}

/* =========================================================================
 * Helper Functions
 * ========================================================================= */

/* Calculate current epoch time in nanoseconds. */
static __always_inline u64 ebph_current_time()
{
    return (u64)bpf_ktime_get_boot_ns() + EBPH_BOOT_EPOCH;
};

/* Look up and return a copy of training data for profile @profile_key
 * at position {@curr, @prev}. */
static __always_inline u8 ebph_get_training_data(u64 profile_key, u16 curr,
                                                 u16 prev)
{
    u32 idx = (curr * EBPH_NUM_SYSCALLS) + prev;
    idx &= (EBPH_NUM_SYSCALLS * EBPH_NUM_SYSCALLS - 1);

    struct ebph_flags_t *flags = ebph_new_flags();
    if (!flags) {
        // TODO log error
        return 0;
    }

    flags = training_data.lookup_or_try_init(&profile_key, flags);
    if (!flags) {
        // TODO log error
        return 0;
    }

    return flags->flags[idx];
}

/* Look up and return a copy of testing data for profile @profile_key
 * at position {@curr, @prev}. */
static __always_inline u8 ebph_get_testing_data(u64 profile_key, u16 curr,
                                                u16 prev)
{
    u32 idx = (curr * EBPH_NUM_SYSCALLS) + prev;
    idx &= (EBPH_NUM_SYSCALLS * EBPH_NUM_SYSCALLS - 1);

    struct ebph_flags_t *flags = ebph_new_flags();
    if (!flags) {
        // TODO log error
        return 0;
    }

    flags = testing_data.lookup_or_try_init(&profile_key, flags);
    if (!flags) {
        // TODO log error
        return 0;
    }

    return flags->flags[idx];
}

static __always_inline int ebph_set_training_data(u64 profile_key, u16 curr,
                                                  u16 prev, u8 new_flag)
{
    u32 idx = (curr * EBPH_NUM_SYSCALLS) + prev;
    idx &= (EBPH_NUM_SYSCALLS * EBPH_NUM_SYSCALLS - 1);

    struct ebph_flags_t *flags = ebph_new_flags();
    if (!flags) {
        // TODO log error
        return 1;
    }

    flags = training_data.lookup_or_try_init(&profile_key, flags);
    if (!flags) {
        // TODO log error
        return 1;
    }

    flags->flags[idx] = new_flag;

    return 0;
}

static __always_inline void ebph_reset_training_data(
    u64 profile_key, struct ebph_task_state_t *s, struct ebph_profile_t *p)
{
    training_data.delete(&profile_key);
    p->anomaly_count  = 0;
    p->train_count    = 0;
    p->last_mod_count = 0;

    // TODO ebph_log_reset
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
    profile->normal_time =
        ebph_current_time() + ebph_get_setting(EBPH_SETTING_NORMAL_WAIT);
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
    for (u32 i = 1; i < EBPH_SEQLEN; i++) {
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

        if (ebph_get_setting(EBPH_SETTING_LOG_SEQUENCES)) {
            ebph_log_new_sequence(task_state, profile, sequence);
        }
    } else {
        lock_xadd(&profile->last_mod_count, 1);

        if (profile->status &
            (EBPH_PROFILE_STATUS_FROZEN | EBPH_PROFILE_STATUS_NORMAL)) {
            return;
        }

        u64 normal_count = 0;
        if (profile->train_count > profile->last_mod_count) {
            normal_count = profile->train_count - profile->last_mod_count;
        }

        if ((normal_count > 0) &&
            (profile->train_count *
                 ebph_get_setting(EBPH_SETTING_NORMAL_FACTOR_DEN) >
             normal_count * ebph_get_setting(EBPH_SETTING_NORMAL_FACTOR))) {
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

static __always_inline void ebph_copy_train_to_test(u64 profile_key)
{
    struct ebph_flags_t *training_flags = training_data.lookup(&profile_key);
    if (!training_flags) {
        return;
    }

    testing_data.update(&profile_key, training_flags);
}

static __always_inline void ebph_start_normal(
    u64 profile_key, struct ebph_task_state_t *task_state,
    struct ebph_profile_t *profile)
{
    ebph_copy_train_to_test(profile_key);

    ebph_log_start_normal(profile_key, task_state, profile);

    ebph_set_normal_time(profile);

    profile->status         = EBPH_PROFILE_STATUS_NORMAL;
    profile->anomaly_count  = 0;
    profile->last_mod_count = 0;
    profile->train_count    = 0;
}

static __always_inline void ebph_stop_normal(
    u64 profile_key, struct ebph_task_state_t *task_state,
    struct ebph_profile_t *profile)
{
    ebph_log_stop_normal(profile_key, task_state, profile);

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

        if (profile->anomaly_count >
            ebph_get_setting(EBPH_SETTING_ANOMALY_LIMIT)) {
            ebph_stop_normal(task_state->profile_key, task_state, profile);
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
        ebph_start_normal(task_state->profile_key, task_state, profile);
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
