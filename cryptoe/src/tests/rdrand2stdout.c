#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "rdrand.h"

void usage(name)
    const char *name;
{
    fprintf(stderr,"usage: %s <32|64>\n",name);
    exit(1);
}

int
main(argc,argv)
    int argc;
    char **argv;
{
    unsigned long int flag;

    if (argc != 2)
        usage(argv[0]);
    flag = strtoul(argv[1],NULL,10);
    if (flag == 32)
    {
        uint32_t r;
        while (1)
        {
            rdrand_32(&r,1);
            write(1,&r,flag/8);
        }
    }
    else if (flag == 64)
    {
        uint64_t r;
        while (1)
        {
            rdrand_64(&r,1);
            write(1,&r,flag/8);
        }
    }
    exit(0);
}


