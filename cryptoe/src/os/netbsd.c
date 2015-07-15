/*
 * Copyright (c) 2015 Sean Davis <dive@endersgame.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS `AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/sysctl.h>
#include <string.h>
#include "rng/os_drbg.h"

#ifdef TESTING
# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <sys/timex.h>
#endif /* TESTING */

int read_os_drbg(obuf,outlen)
    unsigned char *obuf;
    size_t outlen;
{
    static const int mib[2] = {CTL_KERN,KERN_ARND};
    size_t ol;
    ol = outlen;
    return sysctl(mib,2,obuf,&ol,NULL,0);
}

#define OS_SEED_BYTES_AVAILABLE ( \
    (sizeof(long) * 2) + \
    (sizeof(quad) * 2))


#ifdef TESTING
struct mib mibs[] = {
    {{CTL_KERN,KERN_HARDCLOCK_TICKS},"kern.hardclock_ticks",handle_int},
    {{CTL_KERN,KERN_NTPTIME},"kern.ntptime",handle_ntptimeval},
    {{CTL_KERN,KERN_TIMEX},"kern.timex",NULL},
    {{CTL_KERN,KERN_BOOTTIME},"kern.boottime",handle_timespec},
    {{CTL_KERN,KERN_TKSTAT},"kern.tkstat",NULL},
    {{0,0},NULL}};



void
handle_int(n,i)
    const char *n;
    int *i;
{
    printf("%s: %d\n",n,*i);
    free(i);
}

void
handle_timespec(n,i)
    const char *n;
    struct timespec *i;
{
    printf("%s: {%lu,%lu}\n",n,i->tv_sec,i->tv_nsec);
    free(i);
}

void
handle_ntptimeval(n,i)
    const char *n;
    struct ntptimeval *i;
{
    printf("%s: time:       {%lu,%lu}\n",n,i->time);
    printf("%s: maxerror:   %ld\n",n,i->maxerror);
    printf("%s: esterror:   %ld\n",n,i->esterror);
    printf("%s: tai:        %ld\n",n,i->tai);
    printf("%s: time_state: %d\n",n,i->time_state);
    free(i);
}


struct mib {
    int mib[2];
    char *name;
    void (*func)(const char *,void *);
};


int
main(argc,argv)
    int argc;
    char **argv;
{
    int i = 0;
    do {
        uint64_t sz;
        sysctl(mibs[i].mib,2,NULL,&sz,NULL,0);
        printf("%-20s {%d,%d} = %lu\n",
               mibs[i].name,
               mibs[i].mib[0],
               mibs[i].mib[1],
               sz);
        if (mibs[i].func != NULL)
        {
            void *buf;
            buf = (void *)malloc(sz);
            sysctl(mibs[i].mib,2,buf,&sz,NULL,0);
            mibs[i].func(mibs[i].name,buf);
        }
        i++;
    } while (!(mibs[i].mib[0] == 0 && mibs[i].mib[1] == 0));
    printf("ntptimeval: %lu\n",sizeof(struct ntptimeval));
    printf("timex: %lu\n",sizeof(struct timex));
    exit(0);
}

#endif /* TESTING */
