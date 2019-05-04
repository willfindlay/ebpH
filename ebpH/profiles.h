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
 * Licensed under GPL v3 License */

#ifndef PROFILES_H
#define PROFILES_H

#include <linux/sched.h>
#include "defs.h"

// *** pH task data structures ***

typedef struct pH_profile pH_profile;

// a locality
// TODO: implement me
typedef struct
{
    unsigned char win[PH_LOCALITY_WIN];
    int first;
    int total;
    int max;
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

// profile data
// TODO: implement me
typedef struct
{
    u64 last_mod_count;
    u64 train_count;
    unsigned char entry[PH_NUM_SYSCALLS][PH_NUM_SYSCALLS];
}
pH_profile_data;

// per executable profile
// TODO: implement me
struct pH_profile
{
    int normal;
    int frozen;
    time_t normal_time;
    u64 window_size;
    u64 count;
    u64 anomalies;
    char filename[FILENAME_LEN];
};

#endif // PROFILES_H
