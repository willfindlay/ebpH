#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#include "include/folly/tracing/StaticTracepoint.h"

#define MAGIC_RC -1337

#define DO_COMMAND_START          \
    time_t start   = time(NULL);  \
    time_t timeout = start + 200; \
    int rc         = MAGIC_RC;

#define DO_COMMAND_END                          \
    while (rc == MAGIC_RC && start < timeout) { \
        sleep(0.01);                            \
        start = time(NULL);                     \
    }                                           \
                                                \
    if (rc == MAGIC_RC) {                       \
        return EPERM;                           \
    }                                           \
                                                \
    if (rc < 0) {                               \
        errno = -rc;                            \
    }                                           \
                                                \
    return rc;

#define COMMAND0(name, ...)            \
    int name(void)                     \
    {                                  \
        DO_COMMAND_START               \
        FOLLY_SDT(libebph, name, &rc); \
        DO_COMMAND_END                 \
    }

#define COMMAND1(name, arg1_t, arg1)          \
    int name(arg1_t arg1)                     \
    {                                         \
        DO_COMMAND_START                      \
        FOLLY_SDT(libebph, name, &rc, &arg1); \
        DO_COMMAND_END                        \
    }

#define COMMAND2(name, arg1_t, arg1, arg2_t, arg2)   \
    int name(arg1_t arg1, arg2_t arg2)               \
    {                                                \
        DO_COMMAND_START                             \
        FOLLY_SDT(libebph, name, &rc, &arg1, &arg2); \
        DO_COMMAND_END                               \
    }

#define COMMAND3(name, arg1_t, arg1, arg2_t, arg2, arg3_t, arg3) \
    int name(arg1_t arg1, arg2_t arg2, arg3_t arg3)              \
    {                                                            \
        DO_COMMAND_START                                         \
        FOLLY_SDT(libebph, name, &rc, &arg1, &arg2, &arg3);      \
        DO_COMMAND_END                                           \
    }

#define COMMAND4(name, arg1_t, arg1, arg2_t, arg2, arg3_t, arg3, arg4_t, arg4) \
    int name(arg1_t arg1, arg2_t arg2, arg3_t arg3, arg4_t arg4)               \
    {                                                                          \
        DO_COMMAND_START                                                       \
        FOLLY_SDT(libebph, name, &rc, &arg1, &arg2, &arg3, &arg4);             \
        DO_COMMAND_END                                                         \
    }

#define COMMAND5(name, arg1_t, arg1, arg2_t, arg2, arg3_t, arg3, arg4_t, arg4, \
                 arg5_t, arg5)                                                 \
    int name(arg1_t arg1, arg2_t arg2, arg3_t arg3, arg4_t arg4, arg5_t arg5)  \
    {                                                                          \
        DO_COMMAND_START                                                       \
        FOLLY_SDT(libebph, name, &rc, &arg1, &arg2, &arg3, &arg4, &arg5);      \
        DO_COMMAND_END                                                         \
    }

#define COMMAND6(name, arg1_t, arg1, arg2_t, arg2, arg3_t, arg3, arg4_t, arg4, \
                 arg5_t, arg5, arg6_t, arg6)                                   \
    int name(arg1_t arg1, arg2_t arg2, arg3_t arg3, arg4_t arg4, arg5_t arg5,  \
             arg6_t arg6)                                                      \
    {                                                                          \
        DO_COMMAND_START                                                       \
        FOLLY_SDT(libebph, name, &rc, &arg1, &arg2, &arg3, &arg4, &arg5,       \
                  &arg6);                                                      \
        DO_COMMAND_END                                                         \
    }

