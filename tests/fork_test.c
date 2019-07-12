#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

int main()
{
    int pid;
    int ppid;

    ppid = getpid();
    printf("Part PID was %d\n", ppid);
    pid = fork();

    if(pid)
    {
        printf("Child PID was %d\n", pid);
    }
    else
    {
        printf("Child is printing\n");
        printf("Child is printing\n");
        printf("Child is printing\n");
    }
}
