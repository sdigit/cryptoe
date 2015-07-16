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


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#if defined(__linux__)
# include <bsd/string.h>
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "rng/rdrand.h"
#include "rng/nist_ctr_drbg.h"
#include "rng/os_drbg.h"
#include "rng/drbg_api.h"
#include "RFC6234/sha.h"
#include "SHAd256.h"

static int DRBG_STATUS;
static uint64_t clk_monotonic(void);
static uint64_t clk_realtime(void);

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
    ad->ad_vals.clk_real = clk_realtime();
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

void
free_adata(adp)
    ADATA *adp;
{
    memset(adp->ad_bytes,0,AD_SIZE);
    memset(adp,0,sizeof(*adp));
    free(adp);
}

int
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
    uint32_t i;
    // XXX: HKDF to go here
    if (sizeof(*ad) >= drbg_read_len)
    {
        for (i=0;i<len;i++)
        {
            seed[i] = randseed[i] ^ ad->ad_bytes[i];
        }
    }
    else
    {
        // XXX: HKDF
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
    // XXX: HKDF to go here
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
    // XXX: HKDF to go here
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
    // XXX: HKDF to go here
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

int
hmac_random(buf,len,shawut)
    unsigned char *buf;
    uint32_t len;
    enum SHAversion shawut;
{
    uint8_t *sys_rnd_buf;
    uint8_t *urandom_buf;

    assert(len <= USHAHashSize(shawut));
    assert(len >= 16);


    sys_rnd_buf = malloc(len);
    if (sys_rnd_buf == NULL)
        return -1;

    urandom_buf = malloc(len);
    if (urandom_buf == NULL)
        return -1;

    int fd;
    ssize_t rret;
    fd = open("/dev/urandom",O_RDONLY);
    rret = read(fd,urandom_buf,len);
    if (rret != len)
    {
        abort();
    }
    close(fd);

    if (read_os_drbg(sys_rnd_buf,len)!=0)
    {
        abort();
    }

    HMACContext ctx;

    hmacReset(&ctx,shawut,sys_rnd_buf,MIN(USHABlockSize(shawut)-1,len));
    memset(sys_rnd_buf,0,len);
    free(sys_rnd_buf);

    hmacInput(&ctx,urandom_buf,len);
    memset(urandom_buf,0,len);
    free(urandom_buf);

    if (RDRAND_present() == 1)
    {
        uint8_t *rdrand_buf;
        rdrand_buf = malloc(len);
        if (rdrand_buf == NULL)
            return -1;
        hmacInput(&ctx,rdrand_buf,len);
        memset(rdrand_buf,0,len);
        free(rdrand_buf);
    }
 
   uint8_t *digest;
    digest = malloc(USHAHashSize(shawut));

    hmacResult(&ctx,digest);
    memcpy(buf,digest,len);
    memset(digest,0,USHAHashSize(shawut));
    free(digest);
    memset(&ctx,0,sizeof(HMACContext));
 
   return 0;
}
