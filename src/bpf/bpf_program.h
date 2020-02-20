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

/* ===============================================================
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * ===============================================================
 * Keep in sync with src/structs.py
 * ===============================================================
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * =============================================================== */

#ifndef EBPH_H
#define EBPH_H

#include "defs.h"

/* Struct definitions below this line ------------------- */

struct ebpH_lookahead_row
{
    u8 flags[EBPH_NUM_SYSCALLS];
};

struct ebpH_profile_data
{
    struct ebpH_lookahead_row rows[EBPH_NUM_SYSCALLS];
    u64 last_mod_count;
    u64 train_count;
    u64 normal_count;
};

struct ebpH_profile
{
    u8 frozen;
    u8 normal;
    u64 normal_time;
    u64 anomalies;
    struct ebpH_profile_data train;
    struct ebpH_profile_data test;
    u64 key;
    char comm[EBPH_FILENAME_LEN];
};

struct ebpH_locality
{
    u8 win[EBPH_LOCALITY_WIN];
    u32 first;
    u32 total;
    u32 max;
};

struct ebpH_sequence
{
    long seq[EBPH_SEQLEN];
    u8 count;
};

struct ebpH_sequence_stack
{
    struct ebpH_sequence seq[EBPH_SEQSTACK_SIZE];
    u8 top;
    u8 should_pop;
};

struct ebpH_process
{
    struct ebpH_locality alf;
    struct ebpH_sequence_stack stack;
    u32 pid; /* Kernel tgid */
    u32 tid; /* Kernel pid */
    u64 profile_key;
    u8 in_execve;
};

/* Submit perf events related to errors and warnings, not called directly */
static inline void __ebpH_log_error(char *m, int size, struct pt_regs *ctx);
static inline void __ebpH_log_warning(char *m, int size, struct pt_regs *ctx);

static void stats_increment(u8 key);
static void stats_decrement(u8 key);

/* Access runtime parameters */
static int ebpH_is_monitoring();
static int ebpH_is_saving();
static int ebpH_is_logging_new_sequences();

static u32 ebpH_get_parent_tid();
static u32 ebpH_get_group_leader_tid();

static long ebpH_get_lookahead_index(long *curr, long* prev, struct pt_regs *ctx);
static u8 *ebpH_lookahead(struct ebpH_profile_data *data, long curr, long prev);

static int ebpH_process_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_test(struct ebpH_profile_data *data, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_train(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_copy_train_to_test(struct ebpH_profile *profile);
static int ebpH_start_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_stop_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_set_normal_time(struct ebpH_profile *profile, struct pt_regs *ctx);
static int ebpH_check_normal_time(struct ebpH_profile *profile, struct pt_regs *ctx);
static int ebpH_reset_ALF(struct ebpH_process *process, struct pt_regs *ctx);

static struct ebpH_sequence *ebpH_curr_seq(struct ebpH_process *process);
static int ebpH_push_seq(struct ebpH_process *process);
static int ebpH_pop_seq(struct ebpH_process *process);

static int ebpH_add_seq(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_add_anomaly_count(struct ebpH_profile *profile, struct ebpH_process *process, int count, struct pt_regs *ctx);
static int ebpH_process_syscall(struct ebpH_process *process, long *syscall, struct pt_regs *ctx);
static int ebpH_start_tracing(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_create_process(u32 *tid, struct pt_regs *ctx);
static int ebpH_create_profile(u64 *key, char *comm, u8 in_execve, struct pt_regs *ctx);
static int ebpH_reset_profile_data(struct ebpH_profile_data *data, struct pt_regs *ctx);

#endif
/* EBPH_H */
