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

/* This is the BPF program responsible for creating new profiles
 * and establishing training data. It will also signal userspace
 * to freeze a profile and start gathering testing data
 * through a per-profile BPF program. */

#include <linux/sched.h>
#include <linux/fdtable.h>
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/timekeeping.h>

#include "src/c/defs.h"
#include "src/c/message.h"
#include "src/c/utils.h"

/* Tracepoints and kprobes below this line --------------------- */

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    long syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    pH_event *e;
    u64 *key;

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    long syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ppid_tgid = ebpH_get_ppid_tgid();

    return 0;
}

int pH_on_do_open_execat(struct pt_regs *ctx)
{
    //struct file *exec_file;
    //struct dentry *exec_entry;
    //struct inode *exec_inode;
    //pH_profile *p;
    //u64 key = 0;
    //char comm[FILENAME_LEN];

    ///* yoink the file struct */
    //exec_file = (struct file *)PT_REGS_RC(ctx);
    //if(!exec_file || IS_ERR(exec_file))
    //{
    //    /* if the file doesn't exist (invalid execve call), just return here */
    //    return 0;
    //}

    ///* fetch dentry for executable */
    //exec_entry = exec_file->f_path.dentry;
    //if(!exec_entry)
    //{
    //    PH_ERROR("Couldn't fetch the dentry for this executable.", ctx);
    //    return -1;
    //}

    ///* fetch inode for executable */
    //exec_inode = exec_entry->d_inode;
    //if(!exec_inode)
    //{
    //    PH_ERROR("Couldn't fetch the inode for this executable.", ctx);
    //    return -1;
    //}

    ///* we want a key to be comprised of device number in the upper 32 bits */
    ///* and inode number in the lower 32 bits */
    //key  = exec_inode->i_ino;
    //key |= ((u64)exec_inode->i_rdev << 32);

    //u64 pid_tgid = bpf_get_current_pid_tgid();

    ///* update comm with a much better indication of the executable name */
    //struct qstr dn = {};
    //struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    //bpf_probe_read(&dn, sizeof(dn), &exec_entry->d_name);
    //bpf_probe_read(&comm, sizeof(comm), dn.name);

    ///* create a new profile with this key if necessary */
    //pH_create_profile(&key, ctx, comm);

    return 0;
}
