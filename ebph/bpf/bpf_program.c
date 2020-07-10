#include "bpf_program.h"

/* =========================================================================
 * Maps
 * ========================================================================= */

BPF_HASH(task_states, u32, struct ebph_task_state_t, EBPH_MAX_PROCESSES);

BPF_HASH(profiles, u64, struct ebph_profile_t, EBPH_MAX_PROFILES);

/* Inner map for training/testing data */
BPF_F_TABLE("hash", struct ebph_flags_key_t, u8, flags_inner,
            (EBPH_NUM_SYSCALLS * EBPH_NUM_SYSCALLS), BPF_F_NO_PREALLOC);

BPF_TABLE("hash_of_maps$flags_inner", u64, int, training_data,
          EBPH_MAX_PROFILES);

BPF_TABLE("hash_of_maps$flags_inner", u64, int, testing_data,
          EBPH_MAX_PROFILES);

/* =========================================================================
 * Ring Buffers
 * ========================================================================= */

/* =========================================================================
 * BPF Programs
 * ========================================================================= */

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
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

    child_state = ebph_new_task_state(cpid, ctgid, parent_state->profile_key);
    if (!child_state) {
        // TODO: log error
        return 1;
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

    /* Create or look up task_state. */
    struct ebph_task_state_t *task_state =
        ebph_new_task_state(pid, tgid, profile_key);
    if (!task_state) {
        // TODO: log error
        return 1;
    }

    // TODO: reset ALF

    struct ebph_profile_t *profile = ebph_new_profile(profile_key);
    if (!profile) {
        // TODO: log error
        return 1;
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

    return 0;
}

TRACEPOINT_PROBE(signal, signal_deliver)
{
    u32 pid = bpf_get_current_pid_tgid();

    struct ebph_task_state_t *task_state = task_states.lookup(&pid);
    /* Process is not being traced */
    if (!task_state) {
        return 0;
    }

    /* Signal is ignored or not handled */
    if (args->sa_handler == (long)SIG_IGN ||
        args->sa_handler == (long)SIG_DFL) {
        return 0;
    }

    // TODO: Push to stack

    return 0;
}

/* =========================================================================
 * Helper Functions
 * ========================================================================= */

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

    task_state.pid         = pid;
    task_state.tgid        = tgid;
    task_state.profile_key = profile_key;

    return task_states.lookup_or_try_init(&pid, &task_state);
}

/* Create a new profile at @profile_key. */
static __always_inline struct ebph_profile_t *ebph_new_profile(u64 profile_key)
{
    struct ebph_profile_t profile = {};

    profile.status = EBPH_PROFILE_STATUS_TRAINING;

    return profiles.lookup_or_try_init(&profile_key, &profile);
}
