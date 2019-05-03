pH_seq s = {.count = 0};
for(int i = 0; i < SEQLEN; i++)
{
    s.seq[i] = 8888;
}
bpf_get_current_comm(&s.comm, sizeof(s.comm));
