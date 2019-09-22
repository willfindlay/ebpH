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
#include "src/c/utils.h"
#include "src/c/ebpH.h"

#define EBPH_ERROR(MSG, CTX) char m[] = (MSG); __ebpH_log_error(m, sizeof(m), (CTX))
#define EBPH_WARNING(MSG, CTX) char m[] = (MSG); __ebpH_log_warning(m, sizeof(m), (CTX))
#define EBPH_DEBUG(MSG, CTX) char m[] = (MSG); __ebpH_log_debug(m, sizeof(m), (CTX))
#define EBPH_INFO(MSG, CTX) char m[] = (MSG); __ebpH_log_info(m, sizeof(m), (CTX))

BPF_PERF_OUTPUT(ebpH_error);
BPF_PERF_OUTPUT(ebpH_warning);
BPF_PERF_OUTPUT(ebpH_debug);
BPF_PERF_OUTPUT(ebpH_info);

/* log an error -- this function should not be called, use macro EBPH_ERROR instead */
static inline void __ebpH_log_error(char *m, int size, struct pt_regs *ctx)
{
    ebpH_error.perf_submit(ctx, m, size);
}

/* log a warning -- this function should not be called, use macro EBPH_WARNING instead */
static inline void __ebpH_log_warning(char *m, int size, struct pt_regs *ctx)
{
    ebpH_warning.perf_submit(ctx, m, size);
}

/* log a debug message -- this function should not be called, use macro EBPH_DEBUG instead */
static inline void __ebpH_log_debug(char *m, int size, struct pt_regs *ctx)
{
    ebpH_debug.perf_submit(ctx, m, size);
}

/* log a info message -- this function should not be called, use macro EBPH_INFO instead */
static inline void __ebpH_log_info(char *m, int size, struct pt_regs *ctx)
{
    ebpH_info.perf_submit(ctx, m, size);
}

/* BPF tables below this line --------------------- */

/* inode key to executable info */
BPF_HASH(binaries, u64, ebpH_executable);

/* pid_tgid to key for binaries map */
BPF_HASH(pid_to_key, u64, u64, 1024000);

/* Main syscall event buffer */
BPF_PERF_OUTPUT(events);

BPF_PERF_OUTPUT(on_executable_processed);
BPF_PERF_OUTPUT(on_pid_assoc);

/* Function definitions below this line --------------------- */

static u8 ebpH_associate_pid_exe(ebpH_executable *e, u64 *pid_tgid, struct pt_regs *ctx)
{
    if (!e)
    {
        EBPH_ERROR("Could not get executable data -- ebpH_associate_pid_exe", ctx);
        return -1;
    }

    if (!pid_tgid)
    {
        EBPH_ERROR("Could not get pid_tgid -- ebpH_associate_pid_exe", ctx);
        return -1;
    }

    /* TODO: may want to check for shared libraries here */

    pid_to_key.update(pid_tgid, &(e->key));

    ebpH_pid_assoc ass = {.pid=(u32)((*pid_tgid) >> 32), .e=*e};
    on_pid_assoc.perf_submit(ctx, &ass, sizeof(ass));

    return 0;
}

static u8 ebpH_process_executable(u64 *key, u64* pid_tgid, struct pt_regs *ctx, char *comm)
{
    ebpH_executable b;
    ebpH_executable *bp = NULL;

    if (!key)
    {
        EBPH_ERROR("Could not get key -- ebpH_process_executable", ctx);
        return -1;
    }

    if (!comm)
    {
        EBPH_ERROR("Could not get comm -- ebpH_process_executable", ctx);
        return -1;
    }

    if (!pid_tgid)
    {
        EBPH_ERROR("Could not get pid_tgid -- ebpH_process_executable", ctx);
        return -1;
    }

    bp = binaries.lookup(key);
    if (bp)
    {
        return -1;
    }

    b.key = *key;
    bpf_probe_read_str(b.comm, sizeof(b.comm), comm);

    binaries.update(key, &b);
    ebpH_associate_pid_exe(&b, pid_tgid, ctx);

    on_executable_processed.perf_submit(ctx, &b, sizeof(b));

    return 0;
}

/* Tracepoints and kprobes below this line --------------------- */

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u64 syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *key;

    key = pid_to_key.lookup(&pid_tgid);

    if (!key)
    {
        return 0;
    }

    ebpH_event e = {.pid_tgid=pid_tgid, .syscall=syscall, .key=*key};

    events.perf_submit(args, &e, sizeof(e));

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    long syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ppid_tgid = ebpH_get_ppid_tgid();

    return 0;
}

int ebpH_on_do_open_execat(struct pt_regs *ctx)
{
    struct file *exec_file;
    struct dentry *exec_entry;
    struct inode *exec_inode;
    u64 key = 0;
    char comm[EBPH_FILENAME_LEN];

    /* Yoink the file struct */
    exec_file = (struct file *)PT_REGS_RC(ctx);
    if (!exec_file || IS_ERR(exec_file))
    {
        /* If the file doesn't exist (invalid execve call), just return here */
        return -1;
    }

    /* Fetch dentry for executable */
    exec_entry = exec_file->f_path.dentry;
    if (!exec_entry)
    {
        EBPH_ERROR("Couldn't fetch the dentry for this executable -- ebpH_on_do_open_execat", ctx);
        return -1;
    }

    /* Fetch inode for executable */
    exec_inode = exec_entry->d_inode;
    if (!exec_inode)
    {
        EBPH_ERROR("Couldn't fetch the inode for this executable -- ebpH_on_do_open_execat", ctx);
        return -1;
    }

    /* We want a key to be comprised of device number in the upper 32 bits */
    /* and inode number in the lower 32 bits */
    key  = exec_inode->i_ino;
    key |= ((u64)exec_inode->i_rdev << 32);

    u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Load executable name into comm */
    struct qstr dn = {};
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&dn, sizeof(dn), &exec_entry->d_name);
    bpf_probe_read(&comm, sizeof(comm), dn.name);

    /* Store information about this executable */
    ebpH_process_executable(&key, &pid_tgid, ctx, comm);

    return 0;
}
