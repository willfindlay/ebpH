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
 * Licensed under GPL v2 License */

// let profiles.h know that we are in userspace and need some extra definitions
#define USERSPACE

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include "defs.h"
#include "profiles.h"

const char *profile_dir = "/var/lib/pH/profiles";

// TODO: get this working with the training and testing data as well
//       may need a separate structure to submit to eBPF program
pH_profile_payload *load_profile(char *path)
{
    pH_profile_payload *p;
    p = malloc(sizeof(pH_profile_payload));

    // open profile for reading
    FILE *f = fopen(path, "r");
    if(f == NULL)
    {
        printf("%s\n",strerror(errno));
        return NULL;
    }

    while(fread(p, sizeof(pH_profile_payload), 1, f))
    {

    }

    fclose(f);

    return p;
}

void prepare_filename(char *entry, char* filename)
{
    char *c;
    strcpy(filename, profile_dir);
    c = filename + strlen(filename);
    *c = '/';
    c++;
    strcpy(c,entry);
}

int main(int argc, char **argv)
{
    DIR *profiles_dir;
    struct dirent *e;
    char filename[512];
    pH_profile_payload *p;
    int i = 0;

    // open the profile
    profiles_dir = opendir(profile_dir);
    if(profiles_dir == NULL)
        return -1;

    if(argc > 1 && isdigit(argv[1][1]))
    {
        prepare_filename(argv[1], filename);
        p = load_profile(filename);
        free(p);
    }
    else
    {
        for(e = readdir(profiles_dir); e != NULL; e = readdir(profiles_dir))
        {
            if(isdigit(e->d_name[0]))
            {
                prepare_filename(e->d_name, filename);
                p = load_profile(filename);
                free(p);
            }
        }
    }

    return 0;
}
