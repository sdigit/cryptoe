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
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>
#if defined(__linux__)
# include <bsd/string.h>
#endif
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include "rng/nist_ctr_drbg.h"
#include "rng/os_drbg.h"
#include "rng/drbg_api.h"
#include "SHAd256.h"

static int DRBG_STATUS;
static uint64_t clk_monotonic(void);
static uint64_t clk_realtime(void);
static ADATA *new_adata(void);
static void free_adata(ADATA *);
static int rbg_genseed(uint8_t *, uint32_t);

static uint64_t
clk_monotonic()
{
    static struct timespec ts;
    uint64_t n;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    n = (uint64_t) (ts.tv_sec * 1000000000 + ts.tv_nsec);
    memset(&ts,0,sizeof(struct timespec));
    return n;
}

static uint64_t
clk_realtime()
{
    static struct timespec ts;
    uint64_t n;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    n = (uint64_t) (ts.tv_sec * 1000000000 + ts.tv_nsec);
    memset(&ts,0,sizeof(struct timespec));
    return n;
}

ADATA *
new_adata()
{
    ADATA *ad;
    ad = malloc(sizeof(ADATA));
    if (ad == NULL)
        return NULL;

    ad->ad_vals.clk_mono = clk_monotonic();
    if (ad->ad_vals.clk_mono == -1)
    {
        free_adata(ad);
        return NULL;
    }
    ad->ad_vals.clk_real = clk_realtime();
    if (ad->ad_vals.clk_real == -1)
    {
        free_adata(ad);
        return NULL;
    }
    ad->ad_vals.uid = getuid();
    ad->ad_vals.gid = getgid();
    ad->ad_vals.pid = getpid();
    size_t rbg_len = AD_RBG_BYTES;
    if (read_os_drbg(ad->ad_vals.rbg,rbg_len) == -1)
    {
        free_adata(ad);
        return NULL;
    }
    return ad;
}

static void
free_adata(adp)
    ADATA *adp;
{
    memset(adp->ad_bytes,0,AD_SIZE);
    memset(adp,0,sizeof(*adp));
    free(adp);
}

static int
rbg_genseed(seed,len)
    uint8_t *seed;
    uint32_t len;
{
    uint8_t *randseed;
    size_t drbg_read_len;
    ADATA *ad;

    drbg_read_len = len;

    randseed = malloc(drbg_read_len);
    if (randseed == NULL)
        return FAIL;

    memset(randseed,0,drbg_read_len);

    if (read_os_drbg(randseed,drbg_read_len) == -1)
    {
        memset(randseed,0,len);
        free(randseed);
        return FAIL;
    }
    ad = new_adata();
    int i;
    if (sizeof(*ad) >= drbg_read_len)
    {
        for (i=0;i<len;i++)
        {
            seed[i] = randseed[i] ^ ad->ad_bytes[i];
        }
    }
    else
    {
        abort();
    }
    free_adata(ad);
    return OK;
}

RBG *
drbg_new()
{
    RBG *r;
    int nistret;
    int iret;
    r = malloc(sizeof(RBG));
    if (r == NULL)
    {
        return NULL;
    }
    memset(r,0,sizeof(RBG));
    r->rbg_outb = 0;
    r->last_reseed = 0;
    r->rbg_rnd = read_os_drbg;
    r->rbg_adata = new_adata;
    r->rbg_nonce = clk_monotonic;
    r->rbg_seed = rbg_genseed;
    nistret = nist_ctr_initialize();
    if (nistret != 0)
    {
        memset(r,0,sizeof(RBG));
        free(r);
        return NULL;
    }

    uint64_t nonce;
    int noncelen, ei_len, pstrlen;
    uint8_t ei[32];
    char pstr[8];

    ei_len = 32;
    noncelen = 8;
    pstrlen = 8;

    snprintf(pstr,pstrlen,"u%xg%x",getuid(),getgid());

    iret = (r->rbg_rnd)((unsigned char *)ei,(size_t)ei_len);
    if (iret != 0)
    {
        memset(ei,0,ei_len);
        memset(r,0,sizeof(RBG));
        free(r);
        return NULL;
    }

    sha2_state s;
    SHAd256_init(&s);
    SHAd256_update(&s,(uint8_t *)&ei,ei_len);
    memset(&ei,0,ei_len);
    SHAd256_digest(&s,(uint8_t *)&ei,ei_len);
    memset(&s,0,sizeof(sha2_state));

    nonce = (r->rbg_nonce)();

    nistret = nist_ctr_drbg_instantiate(&r->drbg,
                                        (const void *)&ei,      ei_len,
                                        (const void *)&nonce,   noncelen,
                                        (char *)&pstr,          pstrlen);
    if (nistret != 0)
    {
        memset(ei,0,ei_len);
        memset(r,0,sizeof(RBG));
        nonce = 0;
        free(r);
        return NULL;
    }
    DRBG_STATUS = STATUS_OK;
    return r;
}

void
drbg_destroy(r)
    RBG *r;
{
    int nistret;
    nistret = nist_ctr_drbg_destroy(&r->drbg);
    memset(r,0,sizeof(RBG));
    if (nistret != 1)
        return;
}

int
drbg_generate(r,buf,len)
    RBG *r;
    uint8_t *buf;
    uint32_t len;
{
    if (len > 524288)
    {
        return FAIL;
    }

    ADATA *ad;
    unsigned char *ad_rbg_bytes;
    unsigned char ad_rbg_digest[AD_RBG_BYTES];
    sha2_state s;

    ad_rbg_bytes = malloc(AD_RBG_BYTES);
    if (ad_rbg_bytes == NULL)
    {
        return FAIL;
    }
    ad = new_adata();

    memcpy(ad_rbg_bytes,ad->ad_vals.rbg,AD_RBG_BYTES);
    free_adata(ad);
    SHAd256_init(&s);
    SHAd256_update(&s,(uint8_t *)ad_rbg_bytes,AD_RBG_BYTES);
    memset(ad_rbg_bytes,0,AD_RBG_BYTES);
    free(ad_rbg_bytes);
    SHAd256_digest(&s,(uint8_t *)ad_rbg_digest,AD_RBG_BYTES);
    memset(&s,0,sizeof(sha2_state));

    if ((r->rbg_outb - r->last_reseed) + len >= (NIST_CTR_DRBG_RESEED_INTERVAL/2))
    {
        ADATA *rad;
        struct additional_data *advals;
        rad = new_adata();
        advals = &rad->ad_vals;
        int nr;
        nr = drbg_reseed(r,&advals->clk_mono,8);
        free_adata(rad);
        if (nr != OK)
        {
            return FAIL;
        }
        r->last_reseed = r->rbg_outb;
    }

    int nistret;
    nistret = nist_ctr_drbg_generate(&r->drbg,
                                     (void *)buf, (int)len,
                                     (const void *)&ad_rbg_digest, AD_RBG_BYTES);
    r->rbg_outb += len;
    memset(ad_rbg_bytes,0,AD_RBG_BYTES);
    if (nistret != 0)
    {
        return FAIL;
    }
    return OK;
}

int
drbg_reseed(r, ad, ad_len)
    RBG *r;
    void *ad;
    uint32_t ad_len;
{
    uint8_t ei[32];
    int nistret, iret, ei_len;

    ei_len = 32;

    iret = (r->rbg_rnd)((unsigned char *)ei,(size_t)ei_len);
    if (iret != 0)
    {
        return FAIL;
    }

    sha2_state s;
    SHAd256_init(&s);
    SHAd256_update(&s,(uint8_t *)&ei,ei_len);
    memset(&ei,0,ei_len);
    SHAd256_digest(&s,(uint8_t *)&ei,ei_len);
    memset(&s,0,sizeof(sha2_state));

    nistret = nist_ctr_drbg_reseed(&r->drbg,
                                   (const void *)&ei, ei_len,
                                   (const void *)&ad, ad_len);
    if (nistret != 0)
    {
        return FAIL;
    }
    r->last_reseed = r->rbg_outb;
    return OK;
}
