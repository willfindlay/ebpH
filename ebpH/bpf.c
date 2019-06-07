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

#include <linux/sched.h>
#include <linux/fdtable.h>
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/timekeeping.h>
#include "defs.h"
#include "profiles.h"

#define BPF_LICENSE GPL

#define PH_ERROR(MSG, CTX) char m[] = (MSG); __pH_log_error(m, sizeof(m), (CTX)); return -1
#define PH_WARNING(MSG, CTX) char m[] = (MSG); __pH_log_warning(m, sizeof(m), (CTX))

// hard coded stuff
#define THE_KEY 41944417 // this is the inode for anomaly_test on my system
BPF_HASH(lookahead, u64, u8, 98596);

// these structures help with PERF_OUTPUT messages
struct profile_association
{
    u64 key;
    u32 pid;
};

struct profile_copy
{
    u32 ppid;
    u32 pid;
    u64 key;
};

struct debug
{
    u64 n;
};

// profile events
BPF_PERF_OUTPUT(profile_create_event);
BPF_PERF_OUTPUT(profile_load_event);
BPF_PERF_OUTPUT(profile_reload_event);
BPF_PERF_OUTPUT(profile_assoc_event);
BPF_PERF_OUTPUT(profile_disassoc_event);
BPF_PERF_OUTPUT(profile_copy_event);

// error events
BPF_PERF_OUTPUT(pH_error);
BPF_PERF_OUTPUT(pH_warning);

// debugging events
BPF_PERF_OUTPUT(output_number);

// monitoring events
BPF_PERF_OUTPUT(anomaly_event); // TODO: implement this

// counting syscalls
BPF_HISTOGRAM(profiles);
BPF_HISTOGRAM(syscalls);
BPF_HISTOGRAM(forks);
BPF_HISTOGRAM(execves);
BPF_HISTOGRAM(exits);

// Hashmaps {{{

// profiles hashed by device number << 32 | inode number
BPF_HASH(profile, u64, pH_profile);
BPF_HASH(pid_tgid_to_profile_key, u64, u64);

// test data hashed by executable filename
BPF_HASH(test_data,  u64, pH_profile_data);
// training data hashed by executable filename
BPF_HASH(train_data, u64, pH_profile_data);

// sequences hashed by pid_tgid
BPF_HASH(seq, u64, pH_seq);

// }}}
// Helper Functions {{{


// log an error -- this function should not be called, use macro PH_ERROR instead
static inline void __pH_log_error(char *m, int size, struct pt_regs *ctx)
{
    pH_error.perf_submit(ctx, m, size);
}

// log a warning -- this function should not be called, use macro PH_WARNING instead
static inline void __pH_log_warning(char *m, int size, struct pt_regs *ctx)
{
    pH_warning.perf_submit(ctx, m, size);
}


// Generic Helpers {{{

// function that returns the pid_tgid of a process' parent
static u64 pH_get_ppid_tgid()
{
    u64 ppid_tgid;
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    ppid_tgid = ((u64)task->real_parent->tgid << 32) | (u64)task->real_parent->pid;

    return ppid_tgid;
}

// set profile normal time on creation to be one week after creation
static u8 pH_set_normal_time(pH_profile *p, struct pt_regs *ctx)
{
    if(!p)
    {
        PH_ERROR("Profile does not exist -- pH_set_normal_time", ctx);
    }

    u64 time_ns = (u64) bpf_ktime_get_ns();
    time_ns += PH_NORMAL_WAIT;

    p->normal_time = time_ns;

    return 0;
}

// change pH normality based on normal time
static u8 pH_check_normal_time(pH_profile *p, struct pt_regs *ctx)
{
    if(!p)
    {
        PH_WARNING("Profile does not exist -- pH_check_normal_time", ctx);
        return 0;
    }

    u64 time_ns = (u64) bpf_ktime_get_ns();
    if(p->frozen && (time_ns > p->normal_time))
        return 1;

    return 0;
}

// }}}
// Sequences and Localities {{{

// reset a locality for a task
static void pH_reset_locality(pH_seq *s)
{
    for(int i = 0; i < PH_LOCALITY_WIN; i++)
    {
        s->lf.win[i] = 0;
    }

    s->lf.lfc     = 0;
    s->lf.lfc_max = 0;
}

// intialize a pH sequence
static void pH_init_sequence(pH_seq *s)
{
    pH_reset_locality(s);
}

// TODO: this could be a little more performant if we optimize for sequences
//       that don't need to be initialized
static u8 pH_create_or_update_sequence(long *syscall, u64 *pid_tgid)
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
    //if(*syscall == SYS_EXECVE) TODO: no longer resetting sequences on execve for now, this preserves execve anomalies
    //                                 the below if-statement will never get executed at the moment...
    if(0 == 1)
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

    seq.update(pid_tgid, &s);

    return 0;
}

// called when pH detects a fork system call
// we use this to copy the parent's sequence to the child
static u8 pH_copy_sequence_on_fork(u64 *pid_tgid, u64 *ppid_tgid, u64 *fork_ret)
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

static u8 pH_copy_profile_on_fork(u64 *pid_tgid, u64 *ppid_tgid, u64 *fork_ret, struct pt_regs *ctx)
{
    pH_profile *p;
    u64* parent_key;

    if(!pid_tgid || !ppid_tgid || !fork_ret)
        return -1;

    // we want to be inside the child process
    if(*fork_ret != 0)
        return 0;

    // lookup parent profile
    parent_key = pid_tgid_to_profile_key.lookup(ppid_tgid);
    if(!parent_key)
    {
        // this message is commented out because it's extremely annoying when testing
        //PH_WARNING("No parent profile to copy on fork.", ctx);
        return 0;
    }
    p = profile.lookup(parent_key);
    if(!p)
    {
        PH_ERROR("Parent profile not found.", ctx);
    }
    // associate pid with the parent profile
    pid_tgid_to_profile_key.update(pid_tgid, &p->key);

    // notify userspace of profile copying
    struct profile_copy cop = {(*ppid_tgid) >> 32, (*pid_tgid) >> 32, 0};
    bpf_probe_read(&cop.key, sizeof(cop.key), &p->key);
    profile_copy_event.perf_submit(ctx, &cop, sizeof(cop));

    return 0;
}

// }}}
// Profiles and Profile Data {{{

static u8 pH_reset_test_data(u64 key)
{
    pH_profile_data d = {};
    // TODO: initialize lookahead pairs here

    test_data.update(&key, &d);

    return 0;
}

static u8 pH_reset_train_data(u64 key)
{
    pH_profile_data d = {};
    // TODO: initialize lookahead pairs here

    train_data.update(&key, &d);

    return 0;
}

static u8 pH_create_profile(u64 *key, struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // init the profile
    pH_profile p = {.frozen = 0, .normal = 0, .normal_time = 0,
                    .last_mod_count = 0, .train_count = 0,
                    .window_size = 0, .normal_count = 0, .anomalies = 0};
    pH_profile *p_pt;
    pH_profile *temp;

    // set normal_time
    pH_set_normal_time(&p, ctx);

    // set initial comm (this will be overwritten later)
    bpf_get_current_comm(&p.comm, sizeof(p.comm));

//#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
//    bpf_spin_lock(&p.lock);
//#endif

    if(!key)
    {
        PH_ERROR("Failed to fetch key for new profile.", ctx);
    }

    // prevent shared libraries from being written on top of a binary
    u64 *test_key = pid_tgid_to_profile_key.lookup(& pid_tgid);
    if(test_key)
        return 0;

    bpf_probe_read(&p.key, sizeof(p.key), key);

    pH_reset_test_data(p.key);
    pH_reset_train_data(p.key);

    temp = profile.lookup(key);
    if(temp != NULL)
        goto created;

    // create the profile if it does not exist
    temp = profile.lookup_or_init(key, &p);
    bpf_trace_printk("created profile %llu\n", *key);

    // notify userspace of profile creation
    profile_create_event.perf_submit(ctx, &p, sizeof(p));
    profiles.increment(0);

created:
    // associate the profile with the appropriate PID
    pid_tgid_to_profile_key.update(&pid_tgid, key);
    bpf_trace_printk("profile %llu successfully associated with pid %d\n", *key, pid_tgid >> 32);

    // notify userspace of profile asssociation
    struct profile_association ass = {*key, pid_tgid >> 32};
    profile_assoc_event.perf_submit(ctx, &ass, sizeof(ass));

//#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0)
//    bpf_spin_unlock(&p.lock);
//#endif

    return 0;
}

// }}}

// reset locality frame for a given sequence
static u8 pH_reset_ALF(pH_seq *s)
{
    if(!s)
        return -1;

    for(int i=0; i < PH_LOCALITY_WIN; i++)
    {
        s->lf.win[i] = 0;
    }

    s->lf.lfc = 0;
    s->lf.lfc_max = 0;

    // reset task delay
    s->delay = 0;

    return 0;
}

// start normal mode on a profile
static u8 pH_start_normal(pH_profile *p, pH_seq *s)
{
    p->normal = 1;
    p->frozen = 0;
    p->anomalies = 0;
    p->last_mod_count = 0;

    pH_reset_ALF(s);

    //pH_copy_train_to_test TODO: implement this (probably not as an actual function)

    return 0;
}

// test a profile
static int pH_test(pH_profile *p, pH_seq *s, struct pt_regs *ctx)
{
    int mismatches = 0;

    // FIXME: this needs to become generic when maps of maps become available
    if(p->key == THE_KEY)
    {
        if(!s || s->count < 1)
            return mismatches;

        // access at index [syscall][prev]
        for(int i = 1; i < SEQLEN; i++)
        {
            long syscall = s->seq[0];
            long prev = s->seq[i];
            if(prev == EMPTY) // commented this out for now
                break;

            // determine which entry we need
            // TODO: put this in a macro for easy access
            u64 entry = syscall * PH_NUM_SYSCALLS + prev;

            // lookup the syscall data
            u8 init = 0;
            u8 *data = lookahead.lookup_or_init(&entry, &init);

            // check for mismatch
            if(((*data) & (1 << (i-1))) == 0)
                mismatches++;
        }
    }

    return mismatches;
}

// add a sequence to the profile
static u8 pH_add_seq(pH_profile *p, pH_seq *s)
{
    // FIXME: this needs to become generic when maps of maps become available
    if(p->key == THE_KEY)
    {
        if(!s || s->count <= 1)
            return 0;

        // access at index [syscall][prev]
        for(int i = 1; i < SEQLEN; i++)
        {
            long syscall = s->seq[0];
            long prev = s->seq[i];
            if(prev == EMPTY)
                break;

            // determine which entry we need
            // TODO: put this in a macro for easy access
            u64 entry = syscall * PH_NUM_SYSCALLS + prev;

            // either set the entry's data to 0 or retrieve it
            u8 data = 0;
            u8 *temp = lookahead.lookup_or_init(&entry, &data);
            data = *temp;

            // set the lookahead pair
            data |= (1 << (i - 1));
            lookahead.update(&entry, &data);
        }
    }

    return 0;
}

// train a profile on a sequence
static u8 pH_train(pH_profile *p, pH_seq *s, struct pt_regs *ctx)
{
    // update train_count and last_mod_count
    p->train_count++;
    if(pH_test(p, s, ctx))
    {
        PH_WARNING("One or more new sequences have been detected!", ctx);
        if(p->frozen)
            p->frozen = 0;
        pH_add_seq(p, s);
        p->last_mod_count = 0;
    }
    else
    {
        p->last_mod_count++;

        if(p->frozen)
            return 0;

        p->normal_count = p->train_count - p->last_mod_count;

        if((p->normal_count > 0) && (p->train_count * PH_NORMAL_FACTOR_DEN >
                    p->normal_count * PH_NORMAL_FACTOR))
        {
            p->frozen = 1;
            pH_set_normal_time(p, ctx);
        }
    }

    return 0;
}

// stop normal mode
static u8 pH_stop_normal(pH_profile *p, pH_seq *s)
{
    p->normal = 0;
    pH_reset_ALF(s);

    return 0;
}

// operate on a normal process
static u8 pH_process_normal(pH_profile *p, pH_seq *s, struct pt_regs *ctx)
{
    int anomalies = 0;

    if(p->normal)
    {
        anomalies = pH_test(p, s, ctx);
        if(anomalies)
        {
            if(p->anomalies > PH_ANOMALY_LIMIT)
            {
                pH_stop_normal(p,s);
            }
        }
    }

    p->anomalies += anomalies;

    return 0;
}

// process a system call with respect to the process' profile
static u8 pH_process_syscall(pH_profile *p, u64 *pid_tgid, struct pt_regs *ctx)
{
    if(!p)
    {
        PH_ERROR("Could not find profile with key.", ctx);
    }
    if(!pid_tgid)
    {
        PH_ERROR("PID does not exist.", ctx);
    }
    if(!ctx)
    {
        PH_ERROR("Context does not exist.", ctx);
    }

    pH_seq *s;
    pH_profile pro;
    // FIXME: really we should be operating on the profile pointer directly here
    //        in order to do this, we need bpf_spin_lock support, so fix this when it comes out
    //        (we will be locking the profile here)
    bpf_probe_read(&pro, sizeof(pro), p);
    s = seq.lookup(pid_tgid);
    if(!s)
    {
        PH_WARNING("Could not look up sequence (the process has already exited).", ctx);
        return 0;
    }

    pH_process_normal(&pro, s, ctx);

    pH_train(&pro, s, ctx);

    // update normal status if we are frozen and have reached normal_time
    if(pH_check_normal_time(&pro, ctx))
    {
        pH_start_normal(&pro, s);
    }

    profile.update(&pro.key, &pro);
    return 0;
}

// disassociate a profile from a pid
static u8 pH_disassociate_profile(u64 pid_tgid, struct pt_regs *ctx)
{
    u64 *key;
    key = pid_tgid_to_profile_key.lookup(&pid_tgid);
    struct profile_association ass;

    if(!key)
    {
        return 0; // no key to be disassociated
    }

    pid_tgid_to_profile_key.delete(&pid_tgid);

    // notify userspace that the profile has been disassociated
    ass.key = *key;
    ass.pid = pid_tgid;

    // the verifier complains here
    // this probe_read soothes it
    bpf_probe_read(&ass, sizeof(ass), &ass);

    profile_disassoc_event.perf_submit(ctx, &ass, sizeof(ass));

    return 0;
}

// Profile Loading {{{

// load a profile's test data from userspace
static u8 pH_load_test_data(pH_profile_payload *payload)
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
static u8 pH_load_train_data(pH_profile_payload *payload)
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

static u8 pH_load_base_profile(pH_profile_payload *payload, struct pt_regs *ctx)
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

    // notify userspace of the profile being loaded
    profile_load_event.perf_submit(ctx, &p, sizeof(p));

    return 0;
}

// }}}

// }}}
// Tracepoints and Hooks {{{

// hooks onto execve helper responsible for opening the files
// and snags the return value (a file struct pointer)
int pH_on_do_open_execat(struct pt_regs *ctx)
{
    struct file *exec_file;
    struct dentry *exec_entry;
    struct inode *exec_inode;
    pH_profile *p;
    u64 key = 0;

    // yoink the file struct
    exec_file = (struct file *)PT_REGS_RC(ctx);
    if(!exec_file || IS_ERR(exec_file))
    {
        // if the file doesn't exist (invalid execve call), just return here
        return 0;
    }

    // fetch dentry for executable
    exec_entry = exec_file->f_path.dentry;
    if(!exec_entry)
    {
        PH_ERROR("Couldn't fetch the dentry for this executable.", ctx);
    }

    // fetch inode for executable
    exec_inode = exec_entry->d_inode;
    if(!exec_inode)
    {
        PH_ERROR("Couldn't fetch the inode for this executable.", ctx);
    }

    // we want a key to be comprised of device number in the upper 32 bits
    // and inode number in the lower 32 bits
    key  = exec_inode->i_ino;
    key |= ((u64)exec_inode->i_rdev << 32);

    u64 pid_tgid = bpf_get_current_pid_tgid();

    // create a new profile with this key if necessary
    pH_create_profile(&key, ctx);

    // update comm with a much better indication of the executable name
    struct qstr dn = {};
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    pH_profile *pro = profile.lookup(&key);
    if(!pro)
        return 0;
    bpf_probe_read(&dn, sizeof(dn), &exec_entry->d_name);
    bpf_probe_read(&pro->comm, sizeof(pro->comm), dn.name);
    profile.update(&key, pro);

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    long syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    pH_profile *p_pt;
    u64 *key;

    // create or update the sequence for this pid_tgid
    pH_create_or_update_sequence(&args->id, &pid_tgid);

    key = pid_tgid_to_profile_key.lookup(&pid_tgid);

    // log if a fork occurred
    if(syscall == SYS_FORK || syscall == SYS_CLONE || syscall == SYS_VFORK)
    {
        forks.increment(0);
    }

    syscalls.increment(0);

    // process the system call
    if(key)
    {
        p_pt = profile.lookup(key);
        pH_process_syscall(p_pt, &pid_tgid, (struct pt_regs *)args);
    }

    // log if an execve occurred
    if(syscall == SYS_EXECVE)
    {
        // disassociate the profile if it is already associated
        pH_disassociate_profile(pid_tgid, (struct pt_regs *)args);
        execves.increment(0);
    }

    // delete the sequence and disassociate the profile if the process has exited
    if ((syscall == SYS_EXIT) || (syscall == SYS_EXIT_GROUP))
    {
        seq.delete(&pid_tgid);
        pH_disassociate_profile(pid_tgid, (struct pt_regs *)args);

        exits.increment(0);
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
        pH_copy_profile_on_fork(&pid_tgid, &ppid_tgid, (u64 *) &args->ret, (struct pt_regs *)args);
    }

    return 0;
}

// load a profile
int pH_load_profile(struct pt_regs *ctx)
{
    u64 key;
    pH_profile *p;
    pH_profile_payload *payload = (pH_profile_payload *)PT_REGS_RC(ctx);

    if(!payload)
    {
        PH_ERROR("Could not load profile data.", ctx);
    }

    // check if profile is already loaded
    key = payload->profile.key;
    p = profile.lookup(&key);
    if(p)
    {
        //PH_WARNING("Reloading a profile that has already been loaded.", ctx);
        profile_reload_event.perf_submit(ctx, p, sizeof(pH_profile));
        goto reload; // we don't want to increment the number of active profiles if we are reloading
    }

    profiles.increment(0);

reload:

    pH_load_base_profile(payload, ctx);
    pH_load_test_data(payload);
    pH_load_train_data(payload);

    return 0;
}

// }}}
