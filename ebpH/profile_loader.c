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

#include <stdio.h>
#include <stdlib.h>
#include "defs.h"
#include "profiles.h"

// TODO: get this working with the training data as well
//       may need a separate structure to submit to eBPF program
pH_profile_payload *load_profile(char *path)
{
    pH_profile_payload *p;
    p = malloc(sizeof(pH_profile_payload));

    // open profile for reading
    FILE *f = fopen(path, "r");
    if(f == NULL)
        return NULL;

    while(fread(p, sizeof(pH_profile_payload), 1, f))
    {

    }

    return p;
}

int main(int argc, char **argv)
{
    if(argc != 2)
        return -1;

    // open the profile
    char *path = argv[1];
    pH_profile_payload *p = load_profile(path);

    free(p);

    return 0;
}
