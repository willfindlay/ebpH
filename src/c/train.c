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

static u64 ebpH_get_ppid_tgid()
{
    u64 ppid_tgid;
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    ppid_tgid = ((u64)task->real_parent->tgid << 32) | (u64)task->real_parent->pid;

    return ppid_tgid;
}

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

    /* Prevents shared libraries from overwriting binaries */
    // FIXME: this seems to be preventing legitimate overwrites as well.... not sure what to do
    //if (pid_to_key.lookup(pid_tgid))
    //{
    //    return -1;
    //}

    pid_to_key.update(pid_tgid, &(e->key));

    ebpH_pid_assoc ass = {.pid=(u32)((*pid_tgid) >> 32), .key=e->key};
    bpf_probe_read_str(ass.comm, sizeof(ass.comm), e->comm);
    on_pid_assoc.perf_submit(ctx, &ass, sizeof(ass));

    return 0;
}

/* Register information about an executable if necessary
 * and associate PIDs with executables */
static u8 ebpH_process_executable(u64 *key, u64* pid_tgid, struct pt_regs *ctx, char *comm)
{
    ebpH_executable e;
    ebpH_executable *ep = NULL;

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

    ep = binaries.lookup(key);
    if (ep)
    {
        goto associate;
    }

    ep = &e;
    e.key = *key;
    bpf_probe_read_str(e.comm, sizeof(e.comm), comm);

    binaries.update(key, &e);

    on_executable_processed.perf_submit(ctx, &e, sizeof(e));

associate:
    ebpH_associate_pid_exe(ep, pid_tgid, ctx);

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

    /* Hand off event handling to userspace */
    ebpH_event e = {.pid_tgid=pid_tgid, .syscall=syscall, .key=*key};
    events.perf_submit(args, &e, sizeof(e));

    /* Some extra logic for special syscalls */
    if (syscall == EBPH_EXIT || syscall == EBPH_EXIT_GROUP)
    {
        /* Disassociate the PID if the process has exited */
        pid_to_key.delete(&pid_tgid);
    }
    //else if ()

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u64 syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ppid_tgid = ebpH_get_ppid_tgid();
    u64 *key;
    ebpH_executable *e;

    /* Associate pids on fork */
    if (syscall == EBPH_FORK || syscall == EBPH_VFORK || syscall == EBPH_CLONE)
    {
        key = pid_to_key.lookup(&ppid_tgid);

        if (!key)
        {
            /* FIXME: This message is annoying. It will be more relevant when we are actually
             * starting the daemon on system startup. For now, we can comment it out. */
            //EBPH_WARNING("No data to copy to child process.", (struct pt_regs *)args);
            return 0;
        }

        e = binaries.lookup(key);

        if (!e)
        {
            /* We should never ever get here! */
            EBPH_ERROR("A key has become detached from its binary!", (struct pt_regs *)args);
            return -1;
        }

        ebpH_associate_pid_exe(e, &pid_tgid, (struct pt_regs *)args);
    }

    return 0;
}

/* Let's try this instead */
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    char comm[EBPH_FILENAME_LEN];

    bpf_probe_read_str(comm, sizeof(comm), filename);

    ebpH_info.perf_submit(ctx, &comm, sizeof(comm));
    return 0;
}

/* This is a special hook for execve-family calls
 * We need to inspect do_open_execat to snag information about the file
 * If this breaks in a future version of Linux (definitely possible!), I will be sad :( */
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

    /* We want a key to be comprised of device number in the upper 32 bits
     * and inode number in the lower 32 bits */
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
