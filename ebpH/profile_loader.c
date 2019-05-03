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
 * Licensed under MIT License */

// let profiles.h know that we are in userspace and need some extra definitions
#define USERSPACE

#include <stdio.h>
#include "defs.h"
#include "profiles.h"

#define BUFSIZE 1024

pH_seq load_profile(char *path)
{
    // TODO: change this to be profile instead of seq
    pH_seq seq;
    char buf[BUFSIZE];
    char c;
    int  i;
    FILE *f = fopen(path, "r");
    if(f == NULL)
        return NULL;

    while(fread(&seq, sizeof(seq), 1, f))
    {

    }

    printf("Profile loaded!\n");

    printf("%s, %d", seq.comm, seq.count);

    return seq;
}

int main(int argc, char **argv)
{
    if(argc != 2)
        return -1;

    // open the profile
    char *path = argv[1];
    load_profile(path);

    return 0;
}
