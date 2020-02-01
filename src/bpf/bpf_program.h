/* ebpH --  An eBPF intrusion detection program.
 * -------  Monitors system call patterns and detect anomalies.
 * Copyright 2019 William Findlay (williamfindlay@cmail.carleton.ca) and
 * Anil Somayaji (soma@scs.carleton.ca)
 *
 * Based on Anil Somayaji's pH
 *  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
 *  Copyright 2003 Anil Somayaji
 *
 * USAGE: ebphd <COMMAND>
 *
 * Licensed under GPL v2 License */

#ifndef EBPH_H
#define EBPH_H

#include "defs.h"

/* Struct definitions below this line ------------------- */

struct ebpH_profile_data
{
    u8 flags[EBPH_LOOKAHEAD_ARRAY_SIZE];
    u64 last_mod_count;
    u64 train_count;
    u64 normal_count;
    //u64 sequences;
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
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
//    struct bpf_spin_lock lock;
//#endif
};

struct ebpH_locality
{
    u8 win[EBPH_LOCALITY_WIN];
    u32 first;
    u32 total;
    u32 max;
};

struct ebpH_process
{
    struct ebpH_locality alf;
    long seq[EBPH_SEQSTACK_SIZE][EBPH_SEQLEN];
    u8 count;
    u8 stacktop;
    u32 pid; /* Kernel tgid */
    u32 tid; /* Kernel pid */
    u64 exe_key;
    u8 in_execve;
//#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
//    struct bpf_spin_lock lock;
//#endif
};

struct ebpH_anomaly
{
    u32 pid;
    u64 syscall;
    int anomalies;
    u64 key;
    char comm[EBPH_FILENAME_LEN];
};

static inline void __ebpH_log_error(char *m, int size, struct pt_regs *ctx);
static inline void __ebpH_log_warning(char *m, int size, struct pt_regs *ctx);
static long ebpH_get_lookahead_index(long *curr, long* prev, struct pt_regs *ctx);
static int ebpH_process_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_test(struct ebpH_profile_data *data, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_train(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_copy_train_to_test(struct ebpH_profile *profile);
static int ebpH_start_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_stop_normal(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_set_normal_time(struct ebpH_profile *profile, struct pt_regs *ctx);
static int ebpH_check_normal_time(struct ebpH_profile *profile, struct pt_regs *ctx);
static int ebpH_reset_ALF(struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_add_seq(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_add_anomaly_count(struct ebpH_profile *profile, struct ebpH_process *process, int count, struct pt_regs *ctx);
static int ebpH_process_syscall(struct ebpH_process *process, long *syscall, struct pt_regs *ctx);
static u64 ebpH_get_ppid_tgid();
static u64 ebpH_get_glpid_tgid();
static int ebpH_start_tracing(struct ebpH_profile *profile, struct ebpH_process *process, struct pt_regs *ctx);
static int ebpH_create_process(u64 *pid_tgid, struct pt_regs *ctx);
static int ebpH_create_profile(u64 *key, char *comm, u8 in_execve, struct pt_regs *ctx);
static int ebpH_reset_profile_data(struct ebpH_profile_data *data, struct pt_regs *ctx);

#endif
/* EBPH_H */
