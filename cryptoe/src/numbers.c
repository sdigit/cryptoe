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

#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <bsd/string.h>
#include <assert.h>

#ifdef TESTING
# include <stdio.h>
# include <stdlib.h>
# include <math.h>
# include <limits.h>
#endif /* TESTING */

struct cryptoe_value {
    const char *ct_name;
    const char *ct_text;
    unsigned int ct_num;
};

/* return values */

#define CT_OK           0
#define CT_WARN         1
#define CT_FATAL        2

#define CT_RV_OK       { "CT_OK",     "No Error",     0 }
#define CT_RV_WARN     { "CT_WARN",   "Warning",      1 }
#define CT_RV_FATAL    { "CT_FATAL",  "Fatal Error",  2 }

#define CT_RETVALS  CT_OK   \
                    CT_WARN \
                    CT_FATAL

/* macro functions */
#define CT_CHECKLEN(l,minlen,maxlen) (l >= minlen && l <= maxlen)

int
u64tobytearray(in, out, len)
    uint64_t in;
    unsigned char *out;
    uint64_t len;
{
    uint64_t pos = 0;
    assert(CT_CHECKLEN(len,8,8));
    if (!CT_CHECKLEN(len,8,8))
    {
        return CT_FATAL;
    }
    for (pos = 0;pos < 8; pos++)
        out[pos] = in >> (7-pos)*8;
    return CT_OK;
}

int
bytearraytou64array(in, out, len)
    unsigned char *in;
    uint64_t *out;
    uint64_t len;
{
    uint64_t pos, offset, i;
    pos = offset = i = 0;

    assert(len % 8 == 0);

    for (i=0;i<len/8;i++)
    {
        out[i] = (((int64_t)in[offset  ] << 56) & 0xff00000000000000ULL) |
                 (((int64_t)in[offset+1] << 48) & 0x00ff000000000000ULL) |
                 (((int64_t)in[offset+2] << 40) & 0x0000ff0000000000ULL) |
                 (((int64_t)in[offset+3] << 32) & 0x000000ff00000000ULL) |
                 ((         in[offset+4] << 24) & 0x00000000ff000000ULL) |
                 ((         in[offset+5] << 16) & 0x0000000000ff0000ULL) |
                 ((         in[offset+6] <<  8) & 0x000000000000ff00ULL) |
                  (         in[offset+7]        & 0x00000000000000ffULL);
        offset += 8;
    }
}

#ifdef TESTING
int
main(argc,argv)
    int argc;
    char **argv;
{
    int r, i, off;
    unsigned char bytes[8];
    unsigned char buf[25];
    uint64_t test[3];
    uint64_t testret[3];

    test[0] = 17843582476080398235UL;
    test[1] = 6958256255857728915UL;
    test[2] = 943324972469344732UL;

    memset(buf,0,25);
    memset(testret,0,3);
    for (i=0;i<3;i++)
    {
        memset(bytes,0,8);
        printf("u64tobytearray(%lu,%p,%d)\n",test[i],&bytes,8);
        r = u64tobytearray(test[i],&bytes,8);
        printf(" == %d\n",r);
        if (r == CT_OK)
            for (off=0;off<8;off++)
                printf("%p + 0x%02x: %d\n",&bytes,off*8,bytes[off]);
        strlcat(buf,bytes,25);
        memset(bytes,0,8);
    }
    for (i=0;i<24;i++)
    {
        printf("buf[%02d] = %d\n",i,buf[i]);
    }
    r = bytearraytou64array(buf,testret,24);
    for (i=0;i<3;i++)
    {
        printf("%lu\n",test[i]);
        printf("%lu\n",testret[i]);
    }
    return 0;
}
#endif /* TESTING */

