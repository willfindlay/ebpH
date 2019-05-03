// let profiles.h know that we are in userspace and need some extra definitions
#define USERSPACE

#include <stdio.h>
#include "defs.h"
#include "profiles.h"

void save_profile(char *path)
{
    // TODO: change this to be profile instead of seq
    FILE *f = fopen(path, "w");
    if(f == NULL)
        return;

    pH_seq s = {.count = 4, .comm = "test"};

    for(int i = 0; i < 4; i++)
    {
        s.seq[i] = i+1;
    }

    fwrite(&s, sizeof(s), 1, f);

    printf("Profile written!\n");
}

int main(int argc, char **argv)
{
    if(argc != 2)
        return -1;

    // open the profile
    char *path = argv[1];
    save_profile(path);

    return 0;
}
