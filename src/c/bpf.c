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
#include "src/c/ebph.h"

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
BPF_HASH(executables, u64, struct ebpH_executable);

/* ebpH per-executable lookahead pairs */
BPF_HASH(lookahead0, u64, struct ebpH_lookahead_chunk);
BPF_HASH(lookahead1, u64, struct ebpH_lookahead_chunk);
BPF_HASH(lookahead2, u64, struct ebpH_lookahead_chunk);

/* WARNING: NEVER ACCESS THIS DIRECTLY!! */
BPF_ARRAY(lookahead_init, struct ebpH_lookahead_chunk, 1);
//BPF_ARRAY(lookahead_init, struct ebpH_executable, 1);

/* pid_tgid to key for executables map */
BPF_HASH(pid_to_key, u64, u64, 1024000);

/* Main syscall event buffer */
BPF_PERF_OUTPUT(on_executable_processed);
BPF_PERF_OUTPUT(on_pid_assoc);

/* Function definitions below this line --------------------- */

/* TODO: finish this */
static u8 *ebpH_get_lookahead(u64 *key, u32 *curr, u32 *prev, struct pt_regs *ctx)
{
    struct ebpH_lookahead_chunk *chunk = ebpH_get_lookahead_chunk(key, curr, prev, ctx);
    u8 *lookahead = NULL;

    if (!curr)
    {
        EBPH_ERROR("NULL curr syscall -- ebpH_get_lookahead", ctx);
        return NULL;
    }

    if (!prev)
    {
        EBPH_ERROR("NULL prev syscall -- ebpH_get_lookahead", ctx);
        return NULL;
    }

    if (*curr >= EBPH_NUM_SYSCALLS)
    {
        EBPH_ERROR("Access out of bounds (curr) -- ebpH_get_lookahead", ctx);
        return NULL;
    }

    if (*prev >= EBPH_NUM_SYSCALLS)
    {
        EBPH_ERROR("Access out of bounds (prev) -- ebpH_get_lookahead", ctx);
        return NULL;
    }

    return lookahead;
}

/* TODO: finish this */
static u8 *ebpH_update_lookahead(u64 *key, u32 *curr, u32 *prev, u8 *value, struct pt_regs *ctx)
{
    struct ebpH_lookahead_chunk *chunk = ebpH_get_lookahead_chunk(key, curr, prev, ctx);
    u8 *lookahead = NULL;

    if (!value)
    {
        EBPH_ERROR("NULL value -- ebpH_update_lookahead", ctx);
        return NULL;
    }

    if (!curr)
    {
        EBPH_ERROR("NULL curr syscall -- ebpH_update_lookahead", ctx);
        return NULL;
    }

    if (!prev)
    {
        EBPH_ERROR("NULL prev syscall -- ebpH_update_lookahead", ctx);
        return NULL;
    }

    if (*curr >= EBPH_NUM_SYSCALLS)
    {
        EBPH_ERROR("Access out of bounds (curr)... Please update maximum syscall number -- ebpH_update_lookahead", ctx);
        return NULL;
    }

    if (*prev >= EBPH_NUM_SYSCALLS)
    {
        EBPH_ERROR("Access out of bounds (prev)... Please update maximum syscall number  -- ebpH_update_lookahead", ctx);
        return NULL;
    }

    return lookahead;
}

/* Return the correct lookahead chunk data structure according
 * to which current a previous systemcall we are looking at.
 * If the lookahead_chunk is not yet initialized, initialize it with a zeroed struct. */
static struct ebpH_lookahead_chunk *ebpH_get_lookahead_chunk(u64 *key, u32 *curr, u32 *prev, struct pt_regs *ctx)
{
    int zero = 0;
    u8 the_map = -1;
    struct ebpH_lookahead_chunk *init = NULL;
    struct ebpH_lookahead_chunk *lookahead = NULL;
    /* We can't use the normal error macro inside of a switch statement */
    char map_num_error[] = "Invalid map number -- ebpH_get_lookahead_chunk";

    /* get the address of the zeroed lookahead_chunk */
    init = lookahead_init.lookup(&zero);

    if (!init)
    {
        EBPH_ERROR("NULL init -- ebpH_get_lookahead_chunk", ctx);
        return NULL;
    }

    /* copy memory over */
    bpf_probe_read(init, sizeof(struct ebpH_lookahead_chunk), init);

    if (!key)
    {
        EBPH_ERROR("NULL key -- ebpH_get_lookahead_chunk", ctx);
        return NULL;
    }

    if (!curr)
    {
        EBPH_ERROR("NULL curr syscall -- ebpH_get_lookahead_chunk", ctx);
        return NULL;
    }

    if (!prev)
    {
        EBPH_ERROR("NULL prev syscall -- ebpH_get_lookahead_chunk", ctx);
        return NULL;
    }

    if (*curr >= EBPH_NUM_SYSCALLS)
    {
        EBPH_ERROR("Access out of bounds (curr syscall) -- ebpH_get_lookahead_chunk", ctx);
        return NULL;
    }

    if (*prev >= EBPH_NUM_SYSCALLS)
    {
        EBPH_ERROR("Access out of bounds (prev syscall) -- ebpH_get_lookahead_chunk", ctx);
        return NULL;
    }

    /* Calculate which map we need to be accessing */
    the_map = (u8)((*prev * EBPH_NUM_SYSCALLS + *curr) / EBPH_LOOKAHEAD_CHUNK_SIZE);
    switch (the_map)
    {
        /* FIXME: lookup_or_init is not threadsafe (we will need to start using spinlock when possible) */
    case 0:
        lookahead = lookahead0.lookup_or_init(key, init);
        break;
    case 1:
        lookahead = lookahead1.lookup_or_init(key, init);
        break;
    case 2:
        lookahead = lookahead2.lookup_or_init(key, init);
        break;
    default:
        /* "Invalid map number -- ebpH_lookahead" */
        ebpH_error.perf_submit(ctx, &map_num_error, sizeof(map_num_error));
        return NULL;
        break;
    }

    if (!lookahead)
    {
        EBPH_ERROR("Could not lookup or init lookahead chunk -- ebpH_get_lookahead_chunk", ctx);
        return NULL;
    }

    return lookahead;
}

/* Return the parent process id of the task making the current systemcall.
 * This is useful for when we need to copy the parent process' profile during a fork. */
static u64 ebpH_get_ppid_tgid()
{
    u64 ppid_tgid;
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    ppid_tgid = ((u64)task->real_parent->tgid << 32) | (u64)task->real_parent->pid;

    return ppid_tgid;
}

/* Associate a process id to information about whatever executable it is currently running. */
static int ebpH_associate_pid_exe(struct ebpH_executable *e, u64 *pid_tgid, struct pt_regs *ctx)
{
    if (!e)
    {
        EBPH_ERROR("NULL executable data -- ebpH_associate_pid_exe", ctx);
        return -1;
    }

    if (!pid_tgid)
    {
        EBPH_ERROR("NULL pid_tgid -- ebpH_associate_pid_exe", ctx);
        return -1;
    }

    pid_to_key.update(pid_tgid, &(e->key));

    struct ebpH_pid_assoc ass = {.pid=(u32)((*pid_tgid) >> 32), .key=e->key};
    bpf_probe_read_str(ass.comm, sizeof(ass.comm), e->comm);
    on_pid_assoc.perf_submit(ctx, &ass, sizeof(ass));

    return 0;
}

//static int ebpH_create_executable

/* Register information about an executable if necessary
 * and associate PIDs with executables.
 * This is invoked every time the kernel calls on_do_open_execat. */
static int ebpH_process_executable(u64 *key, u64 *pid_tgid, struct pt_regs *ctx, char *comm)
{
    struct ebpH_executable e;
    struct ebpH_executable *ep = NULL;

    if (!key)
    {
        EBPH_ERROR("NULL key -- ebpH_process_executable", ctx);
        return -1;
    }

    if (!comm)
    {
        EBPH_ERROR("NULL comm -- ebpH_process_executable", ctx);
        return -1;
    }

    if (!pid_tgid)
    {
        EBPH_ERROR("NULL pid_tgid -- ebpH_process_executable", ctx);
        return -1;
    }

    ep = executables.lookup(key);
    if (ep)
    {
        goto associate;
    }

    ep = &e;
    e.key = *key;
    bpf_probe_read_str(e.comm, sizeof(e.comm), comm);

    executables.update(key, &e);

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

    /* The juicy stuff goes right here */
    // FIXME: delete me
    u32 test = 0;
    ebpH_get_lookahead_chunk(key, &test, &test, (struct pt_regs *)args);


    /* Some extra logic for special syscalls */
    if (syscall == EBPH_EXIT || syscall == EBPH_EXIT_GROUP)
    {
        /* Disassociate the PID if the process has exited */
        pid_to_key.delete(&pid_tgid);
    }

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u64 syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ppid_tgid = ebpH_get_ppid_tgid();
    u64 *key;
    struct ebpH_executable *e;

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

        e = executables.lookup(key);

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

    /* Prevent shared libraries from overwriting real executables */
    if (!(exec_file->f_mode & 0x111))
    {
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
