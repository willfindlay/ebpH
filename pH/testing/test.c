#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv, char** envp)
{
    if(argc < 2) {
        fprintf(stderr,"ERROR: Please supply a program to run.\n");
        return -1;
    }

    char *prog = argv[1];

    for(int i = argc-2; i > 0; i--) {
        argv[i] = argv[i+1];
    }
    argv[--argc] = NULL;

    printf("My PID is %8d\n",getpid());
    printf("Sleeping for 10 seconds...\n");
    sleep(10);
    printf("Launching %s...\n",prog);

    execvp(prog, argv);

    return 0;
}
