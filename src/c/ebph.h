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

struct ebpH_executable
{
    u64 key;
    char comm[EBPH_FILENAME_LEN];
};

struct ebpH_lookahead_chunk
{
    u8 flags[EBPH_LOOKAHEAD_CHUNK_SIZE];
};

struct ebpH_pid_assoc
{
    u32 pid;
    u64 key;
    char comm[EBPH_FILENAME_LEN];
};

/* TODO: maybe delete */
struct ebpH_event
{
    u64 pid_tgid;
    u64 syscall;
    u64 key;
};

static u8 *ebpH_get_lookahead(u64 *, u32 *, u32 *, struct pt_regs *);
static u8 *ebpH_update_lookahead(u64 *, u32 *, u32 *, u8 *, struct pt_regs *);
static struct ebpH_lookahead_chunk *ebpH_get_lookahead_chunk(u64 *, u32 *, u32*, struct pt_regs *);
static int ebpH_process_executable(u64 *, u64 *, struct pt_regs *, char *);
static int ebpH_associate_pid_exe(struct ebpH_executable *, u64 *, struct pt_regs *);
static u64 ebpH_get_ppid_tgid();

#endif
/* EBPH_H */
