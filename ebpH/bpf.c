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

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/path.h>
#include "defs.h"
#include "profiles.h"

#define BPF_LICENSE GPL

// *** BPF hashmaps ***

// sequences hashed by pid_tgid
BPF_HASH(seq, u64, pH_seq);

// profiles hashed by device number << 32 | inode number
BPF_HASH(profile, u64, pH_profile);
BPF_HASH(pid_tgid_to_profile, u64, pH_profile *);
// test data hashed by executable filename
BPF_HASH(test_data,  u64, pH_profile_data);
// training data hashed by executable filename
BPF_HASH(train_data, u64, pH_profile_data);

// profiles hashed by sequences
BPF_HASH(seq_profile, pH_seq *, pH_profile *);


// *** helper functions ***

// reset a locality for a task
static void pH_reset_locality(pH_seq *s)
{
    for(int i = 0; i < PH_LOCALITY_WIN; i++)
    {
        s->lf.win[i] = 0;
    }

    s->lf.total = 0;
    s->lf.max = 0;
    s->lf.first = PH_LOCALITY_WIN - 1;
}

// intialize a pH sequence
static void pH_init_sequence(pH_seq *s)
{
    pH_reset_locality(s);
}

// function that returns the pid_tgid of a process' parent
static u64 pH_get_ppid_tgid()
{
    u64 ppid_tgid;
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    ppid_tgid = ((u64)task->real_parent->tgid << 32) | (u64)task->real_parent->pid;

    return ppid_tgid;
}

// *** pH sequence create/update subroutines ***

// TODO: this could be a little more performant if we optimize for sequences
//       that don't need to be initialized
static int pH_create_or_update_sequence(long *syscall, u64 *pid_tgid)
{
    int i;
    pH_seq s = {.count = 0};

    if(syscall == NULL || pid_tgid == NULL)
        return -1;

    // intialize sequence data
    for(i = 0; i < SEQLEN; i++)
    {
        s.seq[i] = EMPTY;
    }

    // either init this pid's sequence or copy it from the map
    // if it already exists
    pH_seq *temp;
    temp = seq.lookup_or_init(pid_tgid, &s);
    s = *temp;

    // if we just execve'd we need to wipe the sequence
    if(*syscall == SYS_EXECVE)
    {
        // leave the EXECVE call, wipe the rest
        for(i = 1; i < SEQLEN; i++)
        {
            s.seq[i] = EMPTY;
        }
        s.count = 1;
    }
    // otherwise we simply shift everything over
    else
    {
        // add the system call to the sequence of calls
        s.count++;
        for(i = SEQLEN - 1; i > 0; i--)
        {
            s.seq[i] = s.seq[i-1];
        }
    }

    // insert the syscall at the beginning of the sequence
    s.seq[0] = *syscall;

    if ((*syscall == SYS_EXIT) || (*syscall == SYS_EXIT_GROUP))
    {
        seq.delete(pid_tgid);
    }
    else
    {
        seq.update(pid_tgid, &s);
    }

    return 0;
}

// called when pH detects a fork system call
// we use this to copy the parent's sequence to the child
static int pH_copy_sequence_on_fork(u64 *pid_tgid, u64 *ppid_tgid, u64 *fork_ret)
{
    // child sequence
    pH_seq s = {.count = 0};
    // parent sequence
    pH_seq *parent_seq;

    if(!pid_tgid || !ppid_tgid || !fork_ret)
        return -1;

    // we want to be inside the child process
    if(*fork_ret != 0)
        return 0;

    // fetch parent sequence
    parent_seq = seq.lookup(ppid_tgid);
    if(parent_seq == NULL)
        return 0;

    // copy data to child sequence
    s.count = parent_seq->count;
    for(int i = 0; i < SEQLEN; i++)
    {
        s.seq[i] = parent_seq->seq[i];
    }

    // init child sequence
    seq.lookup_or_init(pid_tgid, &s);

    return 0;
}

static int pH_copy_profile_on_fork(u64 *pid_tgid, u64 *ppid_tgid, u64 *fork_ret)
{
    pH_profile *p_pt;
    pH_profile **temp;

    if(!pid_tgid || !ppid_tgid || !fork_ret)
        return -1;

    // we want to be inside the child process
    if(*fork_ret != 0)
        return 0;

    // lookup parent profile
    temp = pid_tgid_to_profile.lookup(ppid_tgid);
    if(!temp)
    {
        bpf_trace_printk("no parent profile found\n");
        return 0;
    }
    // associate pid with the parent profile
    bpf_probe_read(&p_pt, sizeof(p_pt), temp);
    pid_tgid_to_profile.update(pid_tgid, &p_pt);
    bpf_trace_printk("parent profile associated with pid %d copied to pid %d successfully\n",
            (*ppid_tgid) >> 32, (*pid_tgid) >> 32);

    return 0;
}

// *** pH profile create/update subroutines ***
static int pH_reset_profile_test_data(pH_profile *p)
{
    pH_profile_data d = {.last_mod_count = 0, .train_count = 0};
    // TODO: initialize lookahead pairs here

    if(!p)
    {
        bpf_trace_printk("null profile -- pH_reset_profile_test_data");
        return -1;
    }

    test_data.update(&p->key, &d);

    return 0;
}

static int pH_reset_profile_train_data(pH_profile *p)
{
    pH_profile_data d = {.last_mod_count = 0, .train_count = 0};
    // TODO: initialize lookahead pairs here

    if(!p)
    {
        bpf_trace_printk("null profile -- pH_reset_profile_train_data");
        return -1;
    }

    train_data.update(&p->key, &d);

    return 0;
}

static int pH_create_profile(u64 *key)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // init the profile
    pH_profile p = {.normal = 0, .frozen = 0, .normal_time = 0,
                    .window_size = 0, .count = 0, .anomalies = 0};
    pH_profile *p_pt;
    pH_profile *temp;

    if(!key)
    {
        bpf_trace_printk("failed to fetch key for new profile\n");
        return -1;
    }

    // check to see if a profile is already associated with this PID
    pH_profile **test = pid_tgid_to_profile.lookup(& pid_tgid);
    if(test)
        return 0;

    bpf_probe_read(&p.key, sizeof(p.key), key);

    pH_reset_profile_test_data(&p);
    pH_reset_profile_train_data(&p);

    // create the profile if it does not exist
    temp = profile.lookup_or_init(key, &p);
    bpf_trace_printk("created profile %llu\n", *key);

    // copy profile pointer to stack so we can operate on it
    bpf_probe_read(&p_pt, sizeof(p_pt), &temp);

    // associate the profile with the appropriate PID
    pid_tgid_to_profile.update(&pid_tgid, &p_pt);
    bpf_trace_printk("profile %llu successfully associated with pid %d\n", *key, pid_tgid >> 32);

    return 0;
}

// hooks onto execve helper responsible for opening the files
// and snags the return value (a file struct pointer)
int pH_on_do_open_execat(struct pt_regs *ctx)
{
    struct file *exec_file;
    struct dentry *exec_entry;
    struct inode *exec_inode;
    u64 key = 0;

    if(!ctx)
    {
        bpf_trace_printk("failed to fetch ctx\n");
        return -1;
    }

    // yoink the file struct
    exec_file = (struct file *)PT_REGS_RC(ctx);
    if(!exec_file || IS_ERR(exec_file))
    {
        bpf_trace_printk("failed to fetch exec_file\n");
        return -1;
    }

    // fetch dentry for executable
    exec_entry = exec_file->f_path.dentry;
    if(!exec_entry)
    {
        bpf_trace_printk("failed to fetch exec_entry\n");
        return -1;
    }

    // fetch inode for executable
    exec_inode = exec_entry->d_inode;
    if(!exec_inode)
    {
        bpf_trace_printk("failed to fetch exec_inode\n");
        return -1;
    }

    // we want a key to be comprised of device number in the upper 32 bits
    // and inode number in the lower 32 bits
    key  = exec_inode->i_ino;
    key |= ((u64)exec_inode->i_rdev << 32);

    u64 pid_tgid = bpf_get_current_pid_tgid();

    // create a new profile with this key
    pH_create_profile(&key);

    return 0;
}

// *** BPF tracepoints ***

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    long syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 key;
    pH_profile **p_pt_pt;
    pH_profile *p_pt;
    pH_profile p;

    // create or update the sequence for this pid_tgid
    pH_create_or_update_sequence(&args->id, &pid_tgid);

    // create or update the profile for this executable
    //pH_create_or_update_profile((char *) args->args[0], &pid_tgid, &syscall);

    // log if an execve occurred and disassociate pid with profile
    if(syscall == SYS_EXECVE)
    {
        bpf_trace_printk("execve occurred!\n");
        p_pt_pt = pid_tgid_to_profile.lookup(&pid_tgid);
        if(!p_pt_pt)
        {
            bpf_trace_printk("no previous profile associated with this pid\n");
        }
        else
        {
            bpf_probe_read(&p_pt, sizeof(p_pt), p_pt_pt);
            bpf_probe_read(&p, sizeof(p), p_pt);
            pid_tgid_to_profile.delete(&pid_tgid);
            bpf_trace_printk("disassociated profile %llu with pid %d\n", p.key, pid_tgid >> 32);
        }
    }
    // log if a fork occurred
    if(syscall == SYS_FORK || syscall == SYS_CLONE || syscall == SYS_VFORK)
    {
        bpf_trace_printk("fork occurred!\n");
    }

    return 0;
}

// we need the return value from fork syscalls in order to copy profiles over
TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    long syscall = args->id;
    // get PID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // get parent's PID
    u64 ppid_tgid = pH_get_ppid_tgid();

    // if we are forking, we need to copy our profile to the next
    if(syscall == SYS_FORK || syscall == SYS_CLONE || syscall == SYS_VFORK)
    {
        pH_copy_sequence_on_fork(&pid_tgid, &ppid_tgid, (u64 *) &args->ret);
        pH_copy_profile_on_fork(&pid_tgid, &ppid_tgid, (u64 *) &args->ret);
    }

    return 0;
}

// load a profile's test data from userspace
static int pH_load_test_data(pH_profile_payload *payload)
{
    pH_profile_data d;
    pH_profile_data *temp;
    pH_profile *p;
    u64 key = 0;

    if(!payload)
    {
        bpf_trace_printk("could not load full profile data -- pH_load_test_data \n");
        return -1;
    }

    // grab the appropriate key
    key = payload->profile.key;

    // read in the test data
    bpf_probe_read(&d, sizeof(d), &payload->test);

    // check to see if test data exists in memory
    temp = test_data.lookup(&key);

    // if it does, update it
    if(temp != NULL)
    {
        test_data.update(&key, &d);
    }
    // otherwise, create it
    else
    {
        test_data.lookup_or_init(&key, &d);
    }

    return 0;
}

// load a profile's train data from userspace
static int pH_load_train_data(pH_profile_payload *payload)
{
    pH_profile_data d;
    pH_profile_data *temp;
    pH_profile *p;
    u64 key = 0;

    if(!payload)
    {
        bpf_trace_printk("could not load full profile data -- pH_load_train_data \n");
        return -1;
    }

    // grab the appropriate key
    key = payload->profile.key;

    // read in the train data
    bpf_probe_read(&d, sizeof(d), &payload->train);

    // check to see if train data exists in memory
    temp = train_data.lookup(&key);

    // if it does, update it
    if(temp != NULL)
    {
        train_data.update(&key, &d);
    }
    // otherwise, create it
    else
    {
        train_data.lookup_or_init(&key, &d);
    }

    return 0;
}

static int pH_load_base_profile(pH_profile_payload *payload)
{
    pH_profile p;
    pH_profile *temp;
    u64 key = 0;

    if(!payload)
    {
        bpf_trace_printk("could not load full profile data -- pH_load_base_profile \n");
        return -1;
    }

    bpf_probe_read(&p, sizeof(p), &payload->profile);

    // calculate the hash and lookup the profile
    key = p.key;

    // check to see if profile exists in memory
    temp = profile.lookup(&key);

    // if it does, update it
    if(temp != NULL)
    {
        profile.update(&key, &p);
    }
    // otherwise, create it
    else
    {
        profile.lookup_or_init(&key, &p);
    }
    return 0;
}

// load a profile
int pH_load_profile(struct pt_regs *ctx)
{
    pH_profile_payload *payload = (pH_profile_payload *)PT_REGS_RC(ctx);

    if(!payload)
    {
        bpf_trace_printk("could not load full profile data -- pH_load_profile \n");
        return -1;
    }

    pH_load_base_profile(payload);
    pH_load_test_data(payload);
    pH_load_train_data(payload);

    return 0;
}
