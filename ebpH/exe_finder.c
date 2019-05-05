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

// let profiles.h know that we are in userspace and need some extra definitions
#define USERSPACE

#define PROC_PREFIX "/proc"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "defs.h"
#include "profiles.h"

void setup_exe_fn(char *pid_str, char* fn)
{
    char *c;

    strcpy(fn, PROC_PREFIX);
    c = fn + strlen(fn);
    *c = '/';
    c++;
    strcpy(c, pid_str);
    c = c + strlen(pid_str);
    strcpy(c, "/cmdline");
}

pH_exe_path_mapping *find_exe(char *pid_str)
{
    char path[FILENAME_LEN];
    char byte = 0;
    int i;
    pH_exe_path_mapping *mapping;

    mapping = malloc(sizeof(pH_exe_path_mapping));

    setup_exe_fn(pid_str, path);

    // open profile for reading
    FILE *f = fopen(path, "r");
    if(f == NULL)
        return NULL;

    // read the contents of the file
    for(i = 0; i < FILENAME_LEN - 1 && fread(&byte, 1, 1, f); i++)
    {
        // we don't care about arguments, so break at spaces
        if(byte == ' ')
            break;
        path[i] = byte;
    }
    // null terminate
    path[i] = 0;

    strcpy(mapping->filename, path);
    mapping->pid = atoi(pid_str);

    printf("I should be creating a profile for %s\n", mapping->filename);

    return mapping;
}

int main(int argc, char **argv)
{
    if(argc != 2)
        return -1;

    // map the exe to the pid
    char *pid_str = argv[1];
    pH_exe_path_mapping *temp = find_exe(pid_str);

    free(temp);

    return 0;
}

