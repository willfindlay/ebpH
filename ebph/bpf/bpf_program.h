#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/sched.h>

/* =========================================================================
 * Data Structures and Types
 * ========================================================================= */

struct ebph_task_state_t {
    u32 pid;
    u32 tgid;
    u64 profile_key;
    s8 seqstack_top;
    u8 should_pop;
};

struct ebph_sequence_key_t {
    u32 pid;
    s8 seqstack_top;
};

struct ebph_sequence_t {
    u16 calls[EBPH_SEQLEN];
};

struct ebph_flags_key_t {
    u16 curr;
    u16 prev;
};

/* Current status of the ebpH profile.
 * Possible values: training, frozen, and normal. */
enum ebph_profile_status_t : u8 {
    EBPH_PROFILE_STATUS_NONE     = 0x0,
    EBPH_PROFILE_STATUS_TRAINING = 0x1,
    EBPH_PROFILE_STATUS_FROZEN   = 0x2,
    EBPH_PROFILE_STATUS_NORMAL   = 0x4,
};

/* An ebpH profile. */
struct ebph_profile_t {
    enum ebph_profile_status_t status;
    u64 train_count;
    u64 last_mod_count;
};

/* =========================================================================
 * Helper Functions
 * ========================================================================= */

/* Profile data helpers. */
static __always_inline u8 *ebph_get_training_data(u64 profile_key, u32 curr,
                                                  u32 prev);
static __always_inline u8 *ebph_get_testing_data(u64 profile_key, u32 curr,
                                                 u32 prev);

/* Profile creation. */
static __always_inline struct ebph_profile_t *ebph_new_profile(u64 profile_key);

/* Task state helpers. */
static __always_inline struct ebph_task_state_t *ebph_new_task_state(
    u32 pid, u32 tgid, u64 profile_key);

/* Sequence stack helpers. */
static __always_inline struct ebph_sequence_t *ebph_push_seq(
    struct ebph_task_state_t *task_state);
static __always_inline struct ebph_sequence_t *ebph_pop_seq(
    struct ebph_task_state_t *task_state);
static __always_inline struct ebph_sequence_t *ebph_peek_seq(
    struct ebph_task_state_t *task_state);

static __always_inline void ebph_handle_syscall(
    struct ebph_task_state_t *task_state, u16 syscall);

#endif /* ifndef BPF_PROGRAM_H */
