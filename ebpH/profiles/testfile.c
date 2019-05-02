pH_seq s;
for(int i = 0; i < SEQLEN; i++)
{
    s.seq[i] = 8888;
}
char test[3] = "hi";
bpf_probe_read_str(s.comm, sizeof(test), test);
