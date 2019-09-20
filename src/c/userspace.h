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

/* This header file adds userspace bindings for BPF types.
 * To use it, be sure to include it before including
 * the other header files in this directory. */

#ifndef USERSPACE_H
#define USERSPACE_H

#include <stdint.h>

/* If USERSPACE is defined, define the following types... */
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef long time_t;

#endif
/* USERSPACE_H */
