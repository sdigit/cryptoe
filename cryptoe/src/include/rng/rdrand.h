/* Copyright � 2012, Intel Corporation.  All rights reserved.

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

/*! \file rdrand.h
 *  \brief Public header for rdrand API.
 *
 * This is the public header for the rdrand API. It exposes the three public
 * APIs, which access the rdrand instruction for various data sizes.
 */

/*
 * This version has been modified from the intel sources as follows:
 *
 * 1) 64-bit functions only.
 *
 */
#ifndef RDRAND_H
#define RDRAND_H

#include <inttypes.h>

#define RDRAND_SUCCESS 1
#define RDRAND_NOT_READY -1
#define RDRAND_SUPPORTED -2
#define RDRAND_UNSUPPORTED -3
#define RDRAND_SUPPORT_UNKNOWN -4
#define RDRAND_MASK 0x40000000

#define RETRY_LIMIT 10

int RdRand_cpuid(void);
int RdRand_isSupported(void);
int rdrand_get_n_64(unsigned int n, uint64_t* x);
int rdrand_get_bytes(unsigned int n, unsigned char *buffer);

#endif // RDRAND_H
