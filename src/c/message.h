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

/* Define message macros and perf buffers for logging to userspace.
 * These will need to be registered in the python ebpHD class. */

#ifndef MESSAGE_H
#define MESSAGE_H

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

#endif
/* MESSAGE_H */
