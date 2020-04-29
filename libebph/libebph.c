/* ===============================================================
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * ===============================================================
 * Keep in sync with ebpH/libebph.py
 * ===============================================================
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 * =============================================================== */

#include <stdint.h>

/* Process commands */
void cmd_normalize_process(uint32_t tid) { }
void cmd_tolerize_process(uint32_t tid) { }

/* Profile commands */
void cmd_normalize_profile(uint64_t key) { }
void cmd_tolerize_profile(uint64_t key) { }
void cmd_reset_profile(uint64_t key) { }
