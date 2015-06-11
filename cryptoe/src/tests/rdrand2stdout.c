#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "rdrand.h"

void usage(char *);
void rdrand_out_64(void);
void rdrand_out_n_64(void);
void rdrand_out_bytes(void);
int main(int,char **);

void
usage(name)
    char *name;
{
    printf("Usage: %s <1|2|3>\n\n",name);
    printf("1 = rdrand_64\n");
    printf("2 = rdrand_get_n_64\n");
    printf("3 = rdrand_get_bytes\n");
    exit(0);
}

void
rdrand_out_64()
{
    uint64_t r;
    while(1)
    {
        rdrand_64(&r,1);
        write(1,&r,8);
    }
}

void
rdrand_out_n_64()
{
    uint64_t r[8];
    while(1)
    {
        rdrand_get_n_64(8,r);
        write(1,(char *)r,64);
    }
}

void
rdrand_out_bytes()
{
    unsigned char r[8];
    while(1)
    {
        rdrand_get_bytes(8,r);
        write(1,(char *)r,8);
    }
}

int
main(argc,argv)
    int argc;
    char **argv;
{
    unsigned long flag = 0;
    if (argc != 2)
        usage(argv[0]);
    flag = strtoul(argv[1],NULL,10);
    if (flag < 1 || flag > 3)
        usage(argv[0]);

    switch(flag)
    {
        case 1:
            rdrand_out_64();
            break;
        case 2:
            rdrand_out_n_64();
            break;
        case 3:
            rdrand_out_bytes();
            break;
    }
    exit(0);
}
