#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

int main()
{
    int pid;

    pid = getpid();
    printf("My PID is %d\n", pid);

    char* args[] = {"kill", NULL};

    execvp("kill", args);
}
