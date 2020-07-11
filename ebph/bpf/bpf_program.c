#include "bpf_program.h"

/* =========================================================================
 * Maps
 * ========================================================================= */

/* PID (Kernel) -> Task State */
BPF_HASH(task_states, u32, struct ebph_task_state_t, EBPH_MAX_PROCESSES);

/* Profile Key -> Profile */
BPF_HASH(profiles, u64, struct ebph_profile_t, EBPH_MAX_PROFILES);

/* Inner map for training/testing data flags */
BPF_F_TABLE("hash", struct ebph_flags_key_t, u8, flags_inner,
            (EBPH_NUM_SYSCALLS * EBPH_NUM_SYSCALLS), BPF_F_NO_PREALLOC);

/* Profile Key -> Training Data */
BPF_TABLE("hash_of_maps$flags_inner", u64, int, training_data,
          EBPH_MAX_PROFILES);

/* Profile Key -> Testing Data */
BPF_TABLE("hash_of_maps$flags_inner", u64, int, testing_data,
          EBPH_MAX_PROFILES);

/* {PID (Kernel), Stack Top} -> Sequence Stack */
BPF_F_TABLE("hash", struct ebph_sequence_key_t, struct ebph_sequence_t,
            sequences, (EBPH_MAX_PROCESSES * EBPH_SEQSTACK_FRAMES),
            BPF_F_NO_PREALLOC);

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

    // TODO: reset sequence stack

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

/* Used by ebph_get_training_data and ebph_get_testing_data.
 * Look up and return a pointer to the flag at {@curr, @prev}
 * in map @flags. */
static __always_inline u8 *_ebph_get_profile_data_common(void *flags, u32 curr,
                                                         u32 prev)
{
    u8 *data;

    struct ebph_flags_key_t key = {};

    key.curr = curr;
    key.prev = prev;

    data = bpf_map_lookup_elem(flags, &key);
    if (data) {
        return data;
    }

    u8 init = 0;
    bpf_map_update_elem(flags, &key, &init, BPF_NOEXIST);

    data = bpf_map_lookup_elem(flags, &key);
    return data;
}

/* Look up and return a pointer to training data for profile @profile_key
 * at position {@curr, @prev}. */
static __always_inline u8 *ebph_get_training_data(u64 profile_key, u32 curr,
                                                  u32 prev)
{
    void *flags = training_data.lookup(&profile_key);
    if (!flags) {
        // TODO log error
        return NULL;
    }

    return _ebph_get_profile_data_common(flags, curr, prev);
}

/* Look up and return a pointer to testing data for profile @profile_key
 * at position {@curr, @prev}. */
static __always_inline u8 *ebph_get_testing_data(u64 profile_key, u32 curr,
                                                 u32 prev)
{
    void *flags = testing_data.lookup(&profile_key);
    if (!flags) {
        // TODO log error
        return NULL;
    }

    return _ebph_get_profile_data_common(flags, curr, prev);
}

/* Create a new task_state {@pid, @tgid, @profile_key} at @pid. */
static __always_inline struct ebph_task_state_t *ebph_new_task_state(
    u32 pid, u32 tgid, u64 profile_key)
{
    struct ebph_task_state_t task_state = {};

    task_state.pid          = pid;
    task_state.tgid         = tgid;
    task_state.profile_key  = profile_key;
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

/* Process a new syscall. */
static __always_inline void ebph_handle_syscall(
    struct ebph_task_state_t *task_state, u16 syscall)
{
    // Look up current sequence
    struct ebph_sequence_t *sequence = ebph_peek_seq(task_state);
    if (!sequence) {
        // TODO log error
        return;
    }

    // Insert syscall into sequence
    for (int i = EBPH_SEQLEN - 1; i > 0; i--) {
        sequence->calls[i] = sequence->calls[i - 1];
    }
    sequence->calls[0] = syscall;
}
