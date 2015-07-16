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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <bsd/string.h>
#include <time.h>
#include "rng/os_drbg.h"

#ifndef AF_ALG
# define AF_ALG 38
#endif
#ifndef SOL_ALG
# define SOL_ALG 279
#endif

int
read_os_drbg(buf,buflen)
    unsigned char *buf;
    size_t buflen;
{
    int afd, rfd;
    ssize_t rret;
    struct sockaddr_alg sa;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strlcpy((char *)sa.salg_type,
            "rng",
            sizeof(sa.salg_type));
    strlcpy((char *)sa.salg_name,
            "drbg_pr_ctr_aes128",
            sizeof(sa.salg_name));

    afd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (afd == -1)
    {
        return -1;
    }

    if (bind(afd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    {
        close(afd);
        return -1;
    }

    rfd = accept(afd, NULL, 0);
    if (rfd == -1)
    {
        close(afd);
        return -1;
    }

    rret = read(rfd,buf,buflen);
    if ((size_t)rret != buflen)
    {
        memset(buf,0,buflen);
        return -1;
    }
    close(rfd);
    close(afd);
    return 0;
}

