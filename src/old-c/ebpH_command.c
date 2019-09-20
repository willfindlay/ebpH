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

const char *profile_dir = "/var/lib/ebpH/profiles";

int load_profiles();
pH_profile_payload *load_profile(char *path);
void prepare_filename(char *entry, char* filename);
int check_argc(int argc, int desired);
int print_usage();

// uses laod_profile to load all profiles in profile_dir
int load_profiles()
{
    DIR *profiles_dir;
    struct dirent *e;
    char filename[512];
    pH_profile_payload *p;
    int i = 0;

    // open the profile directory
    profiles_dir = opendir(profile_dir);
    if(profiles_dir == NULL)
        return -1;

    // load each profile
    for(e = readdir(profiles_dir); e != NULL; e = readdir(profiles_dir))
    {
        if(isdigit(e->d_name[0]))
        {
            prepare_filename(e->d_name, filename);
            p = load_profile(filename);
            free(p);
        }
    }

    return 0;
}

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

// prepdend profile_dir to filename
void prepare_filename(char *entry, char* filename)
{
    char *c;
    strcpy(filename, profile_dir);
    c = filename + strlen(filename);
    *c = '/';
    c++;
    strcpy(c,entry);
}

int check_argc(int argc, int desired)
{
    if(argc < desired)
    {
        print_usage();
        return 0;
    }
    return 1;
}

int print_usage()
{
    fprintf(stderr, "Possible commands:\n");
    fprintf(stderr, "load-all\n");
    fprintf(stderr, "load <profile-number>\n");
    fprintf(stderr, "reset-profile <profile-number>\n");
    return -1;
}

int main(int argc, char **argv)
{
    char *command;

    if(argc < 2)
    {
        fprintf(stderr, "Please supply a command.\n");
        print_usage();
        return -1;
    }

    command = argv[1];

    // check command
    if(!strcmp(command, "load-all"))
    {
        load_profiles();
    }
    else if(!strcmp(command, "load"))
    {
        if(check_argc(argc, 2) && isdigit(argv[2]))
        {
            char *path;
            prepare_filename(argv[2], path);
            load_profile(path);
        }
    }

    return 0;
}
