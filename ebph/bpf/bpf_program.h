#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/sched.h>

/* =========================================================================
 * Data Structures and Types
 * ========================================================================= */

typedef struct ebph_task_state_t {
    u32 pid;
    u32 tgid;
    u64 profile_key;
} ebph_task_state_t;

typedef struct ebph_sequence_t {
    u16 calls[EBPH_SEQLEN];
} ebph_sequence_t;

typedef struct ebph_flags_key_t {
    u16 curr;
    u16 prev;
} ebph_flags_key_t;

/* Current status of the ebpH profile.
 * Possible values: training, frozen, and normal. */
typedef enum ebph_profile_status_t : u8 {
    EBPH_PROFILE_STATUS_NONE     = 0x0,
    EBPH_PROFILE_STATUS_TRAINING = 0x1,
    EBPH_PROFILE_STATUS_FROZEN   = 0x2,
    EBPH_PROFILE_STATUS_NORMAL   = 0x4,
} ebph_profile_status_t;

/* An ebpH profile. */
typedef struct ebph_profile_t {
    enum ebph_profile_status_t status;
} ebph_profile_t;

/* =========================================================================
 * Helper Functions
 * ========================================================================= */

/* Profile data helpers. */
static __always_inline u8* ebph_get_training_data(u64 profile_key, u32 curr,
                                                  u32 prev);
static __always_inline u8* ebph_get_testing_data(u64 profile_key, u32 curr,
                                                 u32 prev);

/* Profile creation. */
static __always_inline struct ebph_profile_t* ebph_new_profile(u64 profile_key);

/* Task state helpers. */
static __always_inline struct ebph_task_state_t* ebph_new_task_state(
    u32 pid, u32 tgid, u64 profile_key);

#endif /* ifndef BPF_PROGRAM_H */
