/* anomaly.c */

#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    /* Execute this fake anomaly
     * when we provide an argument */
    if (argc > 1)
        printf("Oops!\n");
    /* Say hello */
    printf("Hello world!\n");

    return 0;
}
