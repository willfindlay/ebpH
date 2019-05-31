/* ebpH --  Monitor syscall sequences and detect anomalies
 * Copyright 2019 Anil Somayaji (soma@scs.carleton.ca) and
 * William Findlay (williamfindlay@cmail.carleton.ca)
 *
 * Based on Sasha Goldshtein's syscount
 *  https://github.com/iovisor/bcc/blob/master/tools/syscount.py
 *  Copyright 2017, Sasha Goldshtein.
 * And on Anil Somayaji's pH
 *  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
 *  Copyright 2003 Anil Somayaji
 *
 * USAGE: ebpH.py <COMMAND>
 *
 * Licensed under GPL v2 License */

#ifndef PROFILES_H
#define PROFILES_H

#include <linux/sched.h>
#include <linux/version.h>
#include <linux/limits.h>
#include "defs.h"

// *** pH task data structures ***

// a locality
// TODO: implement me
typedef struct
{
    u8 win[PH_LOCALITY_WIN];
    int lfc;
    int lfc_max;
}
pH_locality;

// a standard sequence
typedef struct
{
    pH_locality lf;
    u64 seq[SEQLEN];
    u64 count;
    int delay;
}
pH_seq;

// *** pH profile data structures ***

typedef struct
{
    u8 flags[PH_NUM_SYSCALLS];
}
pH_lookahead_pair;

// profile data
// FIXME: given the way I may be implementing this, this struct could be useless
//        might want to get rid of it... for now, added a dumym value so the program will still compile
typedef struct
{
    //u8 pairs[SEQLEN];
    u8 pairs[256];
    u8 dummy; // FIXME: this just lets the program compile for now
}
pH_profile_data;

// per executable profile
// TODO: implement me
typedef struct
{
    u8 state;
    u64 normal_time;
    u64 window_size;
    u64 normal_count;
    u64 last_mod_count; // moved these over from pH_profile_data
    u64 train_count;    // moved these over from pH_profile_data
    u64 anomalies;
    u64 key;
    char comm[FILENAME_LEN];
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
    //struct bpf_spin_lock lock; // https://lists.openwall.net/netdev/2019/01/31/253
#endif
}
pH_profile;

typedef struct
{
    pH_profile profile;
    pH_profile_data test;
    pH_profile_data train;
}
pH_profile_payload;

#endif // PROFILES_H
