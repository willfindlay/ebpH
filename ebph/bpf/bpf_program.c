#include "bpf_program.h"

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    return 0;
}
