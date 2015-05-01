/* Copyright © 2012, Intel Corporation.  All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

-       Redistributions of source code must retain the above copyright notice,
		this list of conditions and the following disclaimer.
-       Redistributions in binary form must reproduce the above copyright
		notice, this list of conditions and the following disclaimer in the
		documentation and/or other materials provided with the distribution.
-       Neither the name of Intel Corporation nor the names of its contributors
		may be used to endorse or promote products derived from this software
		without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
EVENT SHALL INTEL CORPORATION BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE. */

/*
 * This version has been modified from the intel sources as follows:
 *
 * 1) No longer autoconf'd
 * 2) Removed support for Windows
 * 3) Remove support for Intel compiler
 * 4) Assume we're on Linux (BSD needs to be tested)
 * 5) Assume we're using GCC
 * 6) Assume we're on a 64-bit host
 * 7) Assume we're on a CPU with RDRAND (don't test for it)
 *
 */

#include "include/rdrand.h"

#include <string.h>
#include <stdint.h>


#define RETRY_LIMIT 10

typedef uint64_t _wordlen_t;

#define _rdrand_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })
#define _rdrand16_step(x) _rdrand_step(x)
#define _rdrand32_step(x) _rdrand_step(x)
#define _rdrand64_step(x) _rdrand_step(x)

/*
 * I wonder what the impact on the RNG of all these cpuid calls is/was?
 *
 * Removed check for support.
 *
 */
int rdrand_16(uint16_t* x, int retry)
{
    if (retry)
    {
        int i;

        for (i = 0; i < RETRY_LIMIT; i++)
        {
            if (_rdrand16_step(x))
                return RDRAND_SUCCESS;
        }

        return RDRAND_NOT_READY;
    }
    else
    {
				if (_rdrand16_step(x))
					return RDRAND_SUCCESS;
				else
					return RDRAND_NOT_READY;
    }
}

int rdrand_32(uint32_t* x, int retry)
{
    if (retry)
    {
        int i;

        for (i= 0; i < RETRY_LIMIT; i++)
        {
            if (_rdrand32_step(x))
                return RDRAND_SUCCESS;
        }

        return RDRAND_NOT_READY;
    }
    else
    {
            if (_rdrand32_step(x))
                return RDRAND_SUCCESS;
            else
                return RDRAND_NOT_READY;
    }
}

int rdrand_64(uint64_t* x, int retry)
{
    if (retry)
    {
        int i;

        for (i= 0; i < RETRY_LIMIT; i++)
        {
            if (_rdrand64_step(x))
                return RDRAND_SUCCESS;
        }

        return RDRAND_NOT_READY;
    }
    else
    {
            if (_rdrand64_step(x))
                return RDRAND_SUCCESS;
            else
                return RDRAND_NOT_READY;
    }
}



int rdrand_get_n_64(unsigned int n, uint64_t *dest)
{
	int success;
	int count;
	unsigned int i;

	for (i=0; i<n; i++)
	{
		count = 0;
		do
		{
        		success= rdrand_64(dest, 1);
		} while((success == 0) && (count++ < RETRY_LIMIT));
		if (success != RDRAND_SUCCESS) return success;
		dest= &(dest[1]);
	}
	return RDRAND_SUCCESS;
}

int rdrand_get_n_32(unsigned int n, uint32_t *dest)
{
	int success;
	int count;
	unsigned int i;

	for (i=0; i<n; i++)
	{
		count = 0;
		do
		{
        		success= rdrand_32(dest, 1);
		} while((success == 0) && (count++ < RETRY_LIMIT));
		if (success != RDRAND_SUCCESS) return success;
		dest= &(dest[1]);
	}
	return RDRAND_SUCCESS;
}

int rdrand_get_bytes(unsigned int n, unsigned char *dest)
{
	unsigned char *start;
	unsigned char *residualstart;
	_wordlen_t *blockstart;
	_wordlen_t i, temprand;
	unsigned int count;
	unsigned int residual;
	unsigned int startlen;
	unsigned int length;
	int success;

	/* Compute the address of the first 32- or 64- bit aligned block in the destination buffer, depending on whether we are in 32- or 64-bit mode */
	start = dest;
	if (((_wordlen_t) start % (_wordlen_t) sizeof(_wordlen_t)) == 0)
	{
		blockstart = (_wordlen_t *)start;
		count = n;
		startlen = 0;
	}
	else
	{
		blockstart = (_wordlen_t *)(((_wordlen_t)start & ~(_wordlen_t) (sizeof(_wordlen_t)-1) )+(_wordlen_t)sizeof(_wordlen_t));
		count = n - (sizeof(_wordlen_t) - (unsigned int)((_wordlen_t)start % sizeof(_wordlen_t)));
		startlen = (unsigned int)((_wordlen_t)blockstart - (_wordlen_t)start);
	}

	/* Compute the number of 32- or 64- bit blocks and the remaining number of bytes */
	residual = count % sizeof(_wordlen_t);
	length = count/sizeof(_wordlen_t);
	if (residual != 0)
	{
		residualstart = (unsigned char *)(blockstart + length);
	}

	/* Get a temporary random number for use in the residuals. Failout if retry fails */
	if (startlen > 0)
	{
		if ( (success= rdrand_64((uint64_t *) &temprand, 1)) != RDRAND_SUCCESS) return success;
	}

	/* populate the starting misaligned block */
	for (i = 0; i<startlen; i++)
	{
		start[i] = (unsigned char)(temprand & 0xff);
		temprand = temprand >> 8;
	}

	/* populate the central aligned block. Fail out if retry fails */

	if ( (success= rdrand_get_n_64(length, (uint64_t *)(blockstart))) != RDRAND_SUCCESS) return success;
	/* populate the final misaligned block */
	if (residual > 0)
	{
		if ((success= rdrand_64((uint64_t *)&temprand, 1)) != RDRAND_SUCCESS) return success;

		for (i = 0; i<residual; i++)
		{
			residualstart[i] = (unsigned char)(temprand & 0xff);
			temprand = temprand >> 8;
		}
	}

    return RDRAND_SUCCESS;
}

