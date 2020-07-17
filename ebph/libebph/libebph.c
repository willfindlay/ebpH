#include "libebph.h"

COMMAND2(set_setting, int, key, u_int64_t, value)
COMMAND1(normalize_profile, u_int64_t, profile_key)
COMMAND1(normalize_process, u_int32_t, pid)
COMMAND1(sensitize_profile, u_int64_t, profile_key)
COMMAND1(sensitize_process, u_int32_t, pid)
COMMAND1(tolerize_profile, u_int64_t, profile_key)
COMMAND1(tolerize_process, u_int32_t, pid)
