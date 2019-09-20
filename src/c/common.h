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

typedef struct
{
    u8 frozen;
    u8 normal;
    u64 normal_time;
    u64 window_size;
    u64 normal_count;
    u64 last_mod_count;
    u64 train_count;
    u64 anomalies;
    u64 key;
    char comm[FILENAME_LEN];
    struct bpf_spin_lock lock;
}
ebpH_profile;

typedef struct
{
    u64 pid_tgid;
    u64 syscall;
}
ebpH_event;
