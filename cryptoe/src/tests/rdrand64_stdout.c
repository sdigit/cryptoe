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
    uint64_t r;
    while(1)
    {
        rdrand_64(&r,1);
        write(1,&r,sizeof(uint64_t));
    }
    exit(0);
}


