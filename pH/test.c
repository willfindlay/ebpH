#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv, char** envp)
{
  printf("My PID is %d\n",getpid());
  printf("Sleeping for 10 seconds...\n");
  sleep(10);
  printf("Invoking syncs...\n");

  for(int i = 0; i < 300; i++) {
      sync();
      sleep(1);
  }

  return 0;
}
