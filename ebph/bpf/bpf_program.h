/*  ebpH (Extended BPF Process Homeostasis)  A host-based IDS written in eBPF.
 *  ebpH Copyright (C) 2019-2020  William Findlay 
 *  pH   Copyright (C) 1999-2003 Anil Somayaji and (C) 2008 Mario Van Velzen
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
 *  Data structes for BPF program.
 *
 *  2020-Jul-13  William Findlay  Created this.
 *  2020-Jul-17  William Findlay  Added support for ALF window.
 */

#ifndef BPF_PROGRAM_H
#define BPF_PROGRAM_H

#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/sched.h>

/* =========================================================================
 * Data Structures and Types
 * ========================================================================= */

/* Keys into settings map */
enum ebph_setting_key_t : int {
    EBPH_SETTING_MONITORING = 0,
    EBPH_SETTING_LOG_SEQUENCES,
    EBPH_SETTING_NORMAL_WAIT,
    EBPH_SETTING_NORMAL_FACTOR,
    EBPH_SETTING_NORMAL_FACTOR_DEN,
    EBPH_SETTING_ANOMALY_LIMIT,
    EBPH_SETTING_TOLERIZE_LIMIT,
    EBPH_SETTING__END,  // This must be the last entry
};

struct ebph_alf_t {
    u8 win[EBPH_LOCALITY_WIN];
    u8 first;
};

struct ebph_task_state_t {
    u32 pid;
    u32 tgid;
    u64 profile_key;
    char seqstack_top;
    u64 count;
    // ALF stats
    u8 total_lfc;
    u8 max_lfc;
};

struct ebph_sequence_key_t {
    u32 pid;
    char seqstack_top;
};

struct ebph_sequence_t {
    u16 calls[EBPH_SEQLEN];
};

struct ebph_flags_t {
    u8 flags[EBPH_NUM_SYSCALLS * EBPH_NUM_SYSCALLS];
};

/* Current status of the ebpH profile.
 * Possible values: training, frozen, and normal. */
enum ebph_profile_status_t : u8 {
    EBPH_PROFILE_STATUS_TRAINING = 0x1,
    EBPH_PROFILE_STATUS_FROZEN   = 0x2,
    EBPH_PROFILE_STATUS_NORMAL   = 0x4,
};

/* An ebpH profile. */
struct ebph_profile_t {
    enum ebph_profile_status_t status;
    u64 anomaly_count;
    u64 train_count;
    u64 last_mod_count;
    u64 sequences;
    u64 normal_time;
    u64 count;
};

/* =========================================================================
 * Helper Functions
 * ========================================================================= */

/* Calculate current epoch time in nanoseconds. */
static __always_inline u64 ebph_current_time();

/* Look up and return a copy of training data for profile @profile_key
 * at position {@curr, @prev}. */
static __always_inline u8 ebph_get_training_data(u64 profile_key, u16 curr,
                                                 u16 prev);

/* Look up and return a copy of testing data for profile @profile_key
 * at position {@curr, @prev}. */
static __always_inline u8 ebph_get_testing_data(u64 profile_key, u16 curr,
                                                u16 prev);

static __always_inline int ebph_set_training_data(u64 profile_key, u16 curr,
                                                  u16 prev, u8 new_flag);

static __always_inline void ebph_reset_training_data(
    u64 profile_key, struct ebph_task_state_t *s, struct ebph_profile_t *p);

/* Create a new task_state {@pid, @tgid, @profile_key} at @pid. */
static __always_inline struct ebph_task_state_t *ebph_new_task_state(
    u32 pid, u32 tgid, u64 profile_key);

static __always_inline int ebph_reset_alf(struct ebph_task_state_t *s);

/* Calculate normal time for a new profile. */
static __always_inline void ebph_set_normal_time(
    struct ebph_profile_t *profile);

/* Create a new profile at @profile_key. */
static __always_inline struct ebph_profile_t *ebph_new_profile(u64 profile_key);

/* Push a new frame onto the sequence stack for @task_state. */
static __always_inline struct ebph_sequence_t *ebph_push_seq(
    struct ebph_task_state_t *task_state);

/* Pop a frame from the sequence stack for @task_state. */
static __always_inline struct ebph_sequence_t *ebph_pop_seq(
    struct ebph_task_state_t *task_state);

/* Peek a frame from the sequence stack for @task_state. */
static __always_inline struct ebph_sequence_t *ebph_peek_seq(
    struct ebph_task_state_t *task_state);

static __always_inline int ebph_test(struct ebph_task_state_t *task_state,
                                     struct ebph_sequence_t *sequence,
                                     bool use_testing_data);

static __always_inline void ebph_update_training_data(
    struct ebph_task_state_t *task_state, struct ebph_sequence_t *sequence);

static __always_inline void ebph_do_train(struct ebph_task_state_t *task_state,
                                          struct ebph_profile_t *profile,
                                          struct ebph_sequence_t *sequence);

static __always_inline void ebph_add_anomaly_count(
    struct ebph_task_state_t *task_state, struct ebph_profile_t *profile,
    int count);

static __always_inline void ebph_copy_train_to_test(u64 profile_key);

static __always_inline void ebph_start_normal(
    u64 profile_key, struct ebph_task_state_t *task_state,
    struct ebph_profile_t *profile);

static __always_inline void ebph_stop_normal(
    u64 profile_key, struct ebph_task_state_t *task_state,
    struct ebph_profile_t *profile);

static __always_inline void ebph_do_normal(struct ebph_task_state_t *task_state,
                                           struct ebph_profile_t *profile,
                                           struct ebph_sequence_t *sequence);

/* Process a new syscall. */
static __always_inline void ebph_handle_syscall(
    struct ebph_task_state_t *task_state, u16 syscall);

#endif /* ifndef BPF_PROGRAM_H */
