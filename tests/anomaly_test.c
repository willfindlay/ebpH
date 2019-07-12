#include<unistd.h>
#include<string.h>
#include <sys/random.h>

int main(int argc,char **argv)
{
    char *msg = "Hello World!\n";
    if (argc > 1)
    {
        execl("/bin/ls","ls",NULL);
    }
    else
    {
        write(1, msg, strlen(msg));
    }

    return 0;
}
