#ifndef DEFS_H
#define DEFS_H

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

#endif // DEFS_H
