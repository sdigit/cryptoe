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

/*
 * Copyright (c) Thomas DuBuisson
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "rng/rdrand.h"

int RDRAND_present()
{
    uint32_t ax,bx,cx,dx,func=1;
    __asm__ volatile ("cpuid":\
            "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));
    return (cx & 0x40000000);
}

// Returns 1 on success
inline int _rdrand64_step(uint64_t *dest)
{
     unsigned char err;
     asm volatile("rdrand %0 ; setc %1"
                 : "=r" (*dest), "=qm" (err));
     return (int) err;
}

// int rdrand_get_bytes(unsigned int n, unsigned char *dest)
int rdrand_get_bytes(dest, len)
    uint8_t *dest;
    size_t len;
{
    int fail=0;
    uint8_t *p = dest;
    uint8_t *end = dest + len;
    if((uint64_t)p%8 != 0) {
        uint64_t tmp;
        fail |= !_rdrand64_step(&tmp);
        while((uint64_t)p%8 != 0 && p != end && !fail) {
            *p = (uint8_t)(tmp & 0xFF);
            tmp = tmp >> 8;
            p++;
        }
    }
    for(; p <= end - sizeof(uint64_t) && !fail; p+=sizeof(uint64_t)) {
        fail |= !_rdrand64_step((uint64_t *)p);
    }
    if(p != end) {
        uint64_t tmp;
        fail |= !_rdrand64_step(&tmp);
        while(p != end && !fail) {
            *p = (uint8_t)(tmp & 0xFF);
            tmp = tmp >> 8;
            p++;
        }
    }
    return fail;
}

// int rdrand_64(uint64_t* x, int retry)
// int rdrand_get_n_64(unsigned int n, uint64_t *dest)

int rdrand_64(dst)
    uint64_t *dst;
{
    uint64_t r = 0;
    r = _rdrand64_step(dst);
    return r;
}

