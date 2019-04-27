#define SEQLEN         ARG_SEQLEN
#define PID            ARG_PID
#define SYS_EXIT       60
#define SYS_EXIT_GROUP 231

typedef struct {
   u64 seq[SEQLEN];
   u64 count;
} pH_seq;

//typedef u64 pH_seq2[SEQLEN];

BPF_HASH(seq, u64, pH_seq);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    pH_seq lseq = {.count = 0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    long syscall = args->id;
    int i;

    // only trace one PID if specified
    if(PID != -1 && PID != (u32)pid_tgid)
        return 0;

    // initialize data
    for(int i = 0; i < SEQLEN; i++) {
        lseq.seq[i] = 9999;
    }

    pH_seq *s;
    s = seq.lookup_or_init(&pid_tgid, &lseq);
    lseq = *s;

    lseq.count++;
    for (i = SEQLEN-1; i > 0; i--) {
       lseq.seq[i] = lseq.seq[i-1];
    }
    lseq.seq[0] = syscall;


    if ((syscall == SYS_EXIT) || (syscall == SYS_EXIT_GROUP)) {
      seq.delete(&pid_tgid);
    } else {
      seq.update(&pid_tgid, &lseq);
    }

    return 0;
}
