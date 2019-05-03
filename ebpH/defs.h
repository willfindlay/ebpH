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

#ifndef DEFS_H
#define DEFS_H

// we need some extra definitions if we are including this file from userspace
#ifdef USERSPACE
#define TASK_COMM_LEN 16
typedef unsigned long u64;
typedef long time_t;
#endif

// arguments
#define SEQLEN  8

// table size to use for hashmaps
// set to BPF default for now
#define TABLE_SIZE 10240

// pH_task definitions
#define PH_LOCALITY_WIN 128

// pH_profile definitions
#define PH_NUM_SYSCALLS 512

// important syscall definitions
#define SYS_EXIT       60
#define SYS_EXIT_GROUP 231
#define SYS_EXECVE     59
#define SYS_CLONE      56
#define SYS_FORK       57
#define SYS_VFORK      58
#define EMPTY          9999

// structure to help map pids to executables
typedef struct
{
    u64 pid;
    char *filename;
} pH_exe_mapping;

#endif // DEFS_H
