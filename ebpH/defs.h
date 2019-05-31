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

#ifndef DEFS_H
#define DEFS_H

// we need some extra definitions if we are including this file from userspace
#ifdef USERSPACE
#include <stdint.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef long time_t;
#endif

// arguments
#define SEQLEN  8

// table size to use for hashmaps
// set to BPF default for now
#define TABLE_SIZE 10240

// pH_task definitions
#define PH_LOCALITY_WIN 9

// pH_profile definitions
#define PH_NUM_SYSCALLS  314
#define PH_NORMAL_WAIT (u64) (24 * 7 * 3600) // one week in seconds
#define PH_THAWED 0
#define PH_FROZEN 1
#define PH_NORMAL 2

// important syscall definitions
#define SYS_CLONE      56
#define SYS_FORK       57
#define SYS_VFORK      58
#define SYS_EXECVE     59
#define SYS_EXIT       60
#define SYS_EXIT_GROUP 231
#define EMPTY          9999

// size of a filename string
#define FILENAME_LEN 256

#endif // DEFS_H
