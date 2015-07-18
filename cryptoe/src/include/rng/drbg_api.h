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

#ifndef DRBG_API_H
# define DRBG_API_H

#include <inttypes.h>
#include <sys/time.h>
#include "common.h"
#include "rng/nist_ctr_drbg.h"
#include "RFC6234/sha.h"

#define AD_RBG_BITS         (16*8) /* 16 uint8_t's */
#define AD_CLK_BITS         (64*2) /* 3 uint64_t's */
#define AD_XID_BITS         (32*3) /* 3 uint32_t's */
#define AD_RBG_BYTES        AD_RBG_BITS / 8 /* self explanatory */
#define AD_SIZE             (AD_RBG_BITS + AD_CLK_BITS + AD_XID_BITS) / 8

#define DRBG_SEEDLEN        NIST_BLOCK_SEEDLEN_BYTES

/* return values */
#define OK 0
#define FAIL -1
#define RESEED_NEEDED -2

/* status values */
#define STATUS_OK 0
#define STATUS_ERR 1

struct additional_data {
    uint8_t     rbg[AD_RBG_BYTES];  /* output from another RBG */
    uint64_t    clk_mono;           /* monotonic clock */
    uint64_t    clk_real;           /* realtime clock */
    uint32_t    uid;                /* user id */
    uint32_t    gid;                /* group id */
    uint32_t    pid;                /* process id */
};

#define AD_VAL_BYTES    sizeof(struct additional_data)
typedef union {
    struct additional_data ad_vals;
    uint8_t ad_bytes[AD_VAL_BYTES];
} ADATA;

/*
 * RNG instance and minimal required metadata:
 * DRBG,
 * function to get additional data,
 * function to generate a key (or seed, or salt),
 * function to generate a nonce
 */

typedef struct {
    NIST_CTR_DRBG   drbg;
    uint64_t        rbg_bytes_output;
    uint64_t        rbg_requests;
    uint64_t        rbg_last_reseeded;
    int             (*rbg_rnd)(unsigned char *,size_t);
    ADATA *         (*rbg_adata)(void);
    int             (*rbg_key)(uint8_t *,uint32_t);
    uint64_t        (*rbg_nonce)(void);
} RBG;


/* Get and clear Additional Data (as defined above) */
ADATA *new_adata(void);
void dump_adata(ADATA *);
void free_adata(ADATA *);

/* functions used directly */
RBG *drbg_new(void);
void drbg_destroy(RBG *);
int drbg_generate(RBG *, uint8_t *, uint32_t);
int drbg_reseed(RBG *, void *, uint32_t);
int drbg_reseed_ad(RBG *);

#endif /* DRBG_API_H */

