#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv, char** envp)
{
  printf("My PID is %d...\n",getpid());
  printf("Sleeping for 5 seconds...\n");
  sleep(5);
  printf("Invoking ls...\n");

  sync();
  sync();
  sync();

  execvp("ls",argv);

  return 0;
}
