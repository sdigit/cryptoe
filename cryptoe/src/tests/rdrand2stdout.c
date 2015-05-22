#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "rdrand.h"

void usage(const char *);
int main(int,char **);

void usage(name)
    const char *name;
{
    fprintf(stderr,"usage: %s <32|64|bytes> <number per call>\n",name);
    exit(1);
}

int
main(argc,argv)
    int argc;
    char **argv;
{
    unsigned long int flag;
    unsigned long int num;

    if (argc != 3)
        usage(argv[0]);
    flag = strtoul(argv[1],NULL,10);
    num = strtoul(argv[2],NULL,10);
    if (num < 0)
        usage(argv[0]);

    if (flag == 32)
    {
        uint32_t *r;
        r = (uint32_t *)malloc(num);
        if (r == NULL)
        {
            exit(1);
        }
        while (1)
        {
            memset(r,0,num);
            rdrand_get_n_32(num,r);
            write(1,r,num);
            fsync(1);
        }
    }
    else if (flag == 64)
    {
        uint64_t *r;
        r = (uint64_t *)malloc(num);
        if (r == NULL)
        {
            exit(1);
        }
        while (1)
        {
            memset(r,0,num);
            rdrand_get_n_64(num,r);
            write(1,r,num);
            fsync(1);
        }
    }
    else if (!strncmp(argv[1],"bytes",5))
    {
        unsigned char *r;
        r = (unsigned char *)malloc(num);
        if (r == NULL)
        {
            exit(1);
        }
        while (1)
        {
            memset(r,0,num);
            rdrand_get_bytes(num,r);
            write(1,r,num);
        }
    }
    exit(0);
}
