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

//typedef struct
//{
//    u8 frozen;
//    u8 normal;
//    u64 normal_time;
//    u64 window_size;
//    u64 normal_count;
//    u64 last_mod_count;
//    u64 train_count;
//    u64 anomalies;
//    u64 key;
//    char comm[EBPH_FILENAME_LEN];
//    struct bpf_spin_lock lock;
//}
//ebpH_profile;

typedef struct
{
    u64 key;
    char comm[EBPH_FILENAME_LEN];
}
ebpH_executable;

typedef struct
{
    u8 flags[EBPH_LOOKAHEAD_CHUNK_SIZE];
}
ebpH_lookahead_chunk;

typedef struct
{
    u32 pid;
    u64 key;
    char comm[EBPH_FILENAME_LEN];
}
ebpH_pid_assoc;

typedef struct
{
    u64 pid_tgid;
    u64 syscall;
    u64 key;
}
ebpH_event;

static u8 ebpH_process_executable(u64 *key, u64* pid_tgid, struct pt_regs *ctx, char *comm);
static u8 ebpH_associate_pid_exe(ebpH_executable *e, u64 *pid_tgid, struct pt_regs *ctx);
static u64 ebpH_get_ppid_tgid();

#endif
/* EBPH_H */
