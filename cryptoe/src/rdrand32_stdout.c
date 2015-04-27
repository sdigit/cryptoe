#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "rdrand.h"

int
main(argc,argv)
    int argc;
    char **argv;
{
    uint32_t r;
    while(1)
    {
        rdrand_32(&r,1);
        write(1,&r,sizeof(uint32_t));
    }
    exit(0);
}


