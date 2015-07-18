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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <inttypes.h>
#include <string.h>
#include "common.h"

int
bytes_to_hex(dst,dstlen,src,srclen)
    unsigned char *dst;
    size_t dstlen;
    const unsigned char *src;
    size_t srclen;
{
    if (dstlen < (srclen*2)+1)
    {
        return -1;
    }

    size_t i, j;
	for(i=j=0; i<srclen; i++)
	{
		char c;
		c = src[i] / 16; c = (c>9) ? c+'a'-10 : c + '0';
		dst[j++] = c;
		c = src[i] % 16; c = (c>9) ? c+'a'-10 : c + '0';
		dst[j++] = c;
	}
    dst[j] = 0;
    return 0;
}

int
pad(msg,msg_len,padded_len)
    char *msg;
    size_t msg_len;
    size_t padded_len;
{
    if (msg_len > padded_len || msg_len <= 0)
    {
        return -1;
    }
    else if (msg_len == padded_len)
    {
        return 0;
    }

    int pad_len = padded_len - msg_len;
    size_t pos;
    for (pos=0;pos<pad_len;pos++)
    {
        msg[msg_len+pos] = pos;
    }
    return pos;
}

void
uname_to_kilobit(b)
    void *b;
{
    char *buf;
    uint8_t *iptr;
    unsigned int i, p;
    struct utsname u;

    buf = (char *)b;
    iptr = (uint8_t *)buf;

    p = 0;

    for (i=0;i<strlen(u.sysname);i++)
    {
        iptr[p++] ^= u.sysname[i];
        p %= 128;
    }
    for (i=0;i<strlen(u.nodename);i++)
    {
        iptr[p++] ^= u.nodename[i];
        p %= 128;
    }
    for (i=0;i<strlen(u.release);i++)
    {
        iptr[p++] ^= u.release[i];
        p %= 128;
    }
    for (i=0;i<strlen(u.version);i++)
    {
        iptr[p++] ^= u.version[i];
        p %= 128;
    }
    for (i=0;i<strlen(u.machine);i++)
    {
        iptr[p++] ^= u.machine[i];
        p %= 128;
    }
    memset(&u,0,sizeof(struct utsname));
}
