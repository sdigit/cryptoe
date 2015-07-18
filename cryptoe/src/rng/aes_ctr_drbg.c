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
#include "common.h"
#include "rng/rdrand.h"
#include "rng/nist_ctr_drbg.h"
#include "rng/os_drbg.h"
#include "rng/drbg_api.h"
#include "RFC6234/sha.h"

#define RBG_KEYLEN      64
#define HKDF_INFO_LEN   (size_t)32

typedef struct HKDF_buffers {
    uint8_t         salt[RBG_KEYLEN];       /* (EXT) salt*/
    uint8_t         ikm[RBG_KEYLEN];        /* (EXT) Input Keying Material */
    uint8_t         prk[RBG_KEYLEN];        /* (EXT|EXP) Pseudo-Random Key */
    uint8_t         okm[RBG_KEYLEN];        /* (EXP) Output Keying Material */
    unsigned char   info[HKDF_INFO_LEN];    /* (EXP) Info String */
    struct HKDFContext context;             /* (EXT|EXP) RFC6434 Context */
} HKDF_buffers;

typedef struct rbg_buffers {
    int             key_len;        /* DRBG entropy input buffer size */
    int             nonce_len;      /* size of nonce */
    uint64_t        nonce;          /* nonce for init of CTR_DRBG */
    HKDF_buffers    hkdf;           /* storage for HKDF information */
} rbg_buffers;

static int DRBG_STATUS;
static uint64_t clk_monotonic(void);
static uint64_t clk_realtime(void);
static int genkey_rbg(uint8_t *,uint32_t);

static rbg_buffers *rbg_alloc_buffers(void);
static void rbg_destroy_buffers(rbg_buffers *);

static RBG *rbg_alloc(void);
static void rbg_destroy(RBG *);

static rbg_buffers *
rbg_alloc_buffers()
{
    rbg_buffers *ptr;
    ptr = (struct rbg_buffers *)malloc(sizeof(rbg_buffers));
    if (ptr == NULL)
    {
        return NULL;
    }
    HKDF_buffers *h;

    ptr->key_len = 64;
    ptr->nonce_len = 8;

    h = (HKDF_buffers *)&ptr->hkdf;
    memset(h->salt,0,64);
    memset(h->ikm,0,64);
    memset(h->okm,0,64);
    memset(h->prk,0,64);
    memset(&h->context,0,sizeof(HKDFContext));
    return ptr;
}

void
rbg_destroy_buffers(ptr)
    struct rbg_buffers *ptr;
{
    memset(ptr,0,sizeof(struct rbg_buffers));
    ptr->key_len = 0;
    ptr->nonce_len = 0;
    free(ptr);
}


/*
 * Get the current value of the monotonic clock
 * Return it as an unsigned 64 bit integer
 */
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

/*
 * Get the current value of the realtime clock
 * Return it as an unsigned 64 bit integer
 */
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

static RBG *
rbg_alloc()
{
    RBG *r;
    r = malloc(sizeof(RBG));
    if (r == NULL)
    {
        return NULL;
    }
    memset(r,0,sizeof(RBG));

    r->rbg_bytes_output     = 0;
    r->rbg_requests         = 0;
    r->rbg_last_reseeded    = 0;
    r->rbg_rnd              = read_os_drbg;
    r->rbg_adata            = new_adata;
    r->rbg_nonce            = clk_monotonic;
    r->rbg_key              = genkey_rbg;
    return r;
}

static void
rbg_destroy(ptr)
    RBG *ptr;
{
    memset(ptr,0,sizeof(RBG));
    free(ptr);
};

static int
genkey_rbg(seed,len)
    uint8_t *seed;
    uint32_t len;
{
    if (len > 64)
    {
        return FAIL;
    }

    uint8_t sysid_kb[128];
    uint8_t digest[64];
    uint8_t *rnd_in;
    int hmnope = 0;
    ADATA *ad;
    HMACContext h;

    rnd_in = malloc(len);
    if (rnd_in == NULL)
        return FAIL;

    memset(rnd_in,0,len);
    if (read_os_drbg(rnd_in,len) == -1)
    {
        memset(rnd_in,0,len);
        free(rnd_in);
        return FAIL;
    }
    uname_to_kilobit(&sysid_kb);
    ad = new_adata();
    memset(ad->ad_vals.rbg,0,AD_RBG_BYTES);

    hmnope = hmacReset(&h,SHA512,(const unsigned char *)&ad,64) ||
                hmacInput(&h,(const unsigned char *)&sysid_kb,128) ||
                hmacResult(&h,(uint8_t *)&digest);
    free_adata(ad);
    memset(&h,0,sizeof(HMACContext));
    memset(&sysid_kb,0,128);
    if (hmnope)
    {
        memset(rnd_in,0,len);
        free(rnd_in);
        return FAIL;
    }

    int i;

    for (i=0;i<64;i++)
    {
        seed[i] = rnd_in[i] ^ digest[i];
    }
    memset(rnd_in,0,len);
    free(rnd_in);
    return OK;
}

RBG *
drbg_new()
{
    RBG *r;
    rbg_buffers *rb;
    int iret;
    union {
        uint32_t id[2];
        char str[8];
    } p;


    p.id[0] = getpid();
    p.id[1] = getuid();

    r = rbg_alloc();
    if (r == NULL)
    {
        return NULL;
    }
    iret = nist_ctr_initialize();
    if (iret != 0)
    {
        rbg_destroy(r);
        return NULL;
    }
    rb = rbg_alloc_buffers();
    if (rb == NULL)
    {
        rbg_destroy(r);
        return NULL;
    }

    rb->nonce = (r->rbg_nonce)();


    iret =  (!(strlcpy((char *)rb->hkdf.info,
                "CTR_DRBG+DF+PR+HKDF(256)",
                 HKDF_INFO_LEN) <= HKDF_INFO_LEN)) ||
            (r->rbg_rnd)((unsigned char *)rb->hkdf.salt,
                (size_t)rb->key_len) ||
            (r->rbg_key)((uint8_t *)rb->hkdf.ikm,
                rb->key_len) ||
            hkdfExtract(SHA512,
                (const unsigned char *)rb->hkdf.salt,
                rb->key_len,
                (const unsigned char *)rb->hkdf.salt,
                rb->key_len,
                rb->hkdf.prk) ||
            hkdfExpand(SHA512,
                rb->hkdf.prk,
                USHAHashSize(SHA512),
                rb->hkdf.info,
                HKDF_INFO_LEN,
                rb->hkdf.okm,
                rb->key_len) ||
            nist_ctr_drbg_instantiate(&(r->drbg),
                rb->hkdf.okm,
                rb->key_len,
                &rb->nonce,
                rb->nonce_len,
                p.str,
                sizeof(p));

    rbg_destroy_buffers(rb);
    memset((void *)&p,0,8);
    rb = NULL;

    if (iret != 0)
    {
        rbg_destroy_buffers(rb);
        rbg_destroy(r);
        DRBG_STATUS = STATUS_ERR;
        return NULL;
    }

    DRBG_STATUS = drbg_reseed_ad(r) == 0 ? STATUS_OK : STATUS_ERR;
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
    if (DRBG_STATUS != STATUS_OK)
    {
        return FAIL;
    }
    if (len > 524288)
    {
        return FAIL;
    }

    if ((r->rbg_bytes_output - r->rbg_last_reseeded) + len >= (NIST_CTR_DRBG_RESEED_INTERVAL/2))
    {
        int nr;
        nr = drbg_reseed_ad(r);
        if (nr != OK)
        {
            return FAIL;
        }
    }

    int iret;
    ADATA *ad;
    ad = new_adata();
    iret = nist_ctr_drbg_generate(&r->drbg,
                                  (void *)buf, (int)len,
                                  (const void *)ad, sizeof(*ad));
    free_adata(ad);
    if (iret != 0)
    {
        DRBG_STATUS = STATUS_ERR;
        return FAIL;
    }

    rbg_buffers *rb;
    rb = rbg_alloc_buffers();
    if (rb == NULL)
    {
        DRBG_STATUS = STATUS_ERR;
        return FAIL;
    }

    memcpy(rb->hkdf.ikm,buf,len);
    memset(buf,0,len);
    genkey_rbg(rb->hkdf.salt,len);

    if (hkdf(SHA512,
        rb->hkdf.salt,len,
        rb->hkdf.ikm,len,
        (const unsigned char *)"CTR_DRBG->HKDF->OUTPUT",22,
        buf,len))
    {
        DRBG_STATUS = STATUS_ERR;
        return FAIL;
    }

    r->rbg_bytes_output += len;
    return OK;
}

int
drbg_reseed(r, ad, ad_len)
    RBG *r;
    void *ad;
    uint32_t ad_len;
{
    if (DRBG_STATUS != STATUS_OK)
    {
        return FAIL;
    }

    uint8_t ei[48];
    int nistret, iret, ei_len;

    ei_len = 48;

    iret = (r->rbg_rnd)((unsigned char *)ei,(size_t)ei_len);
    if (iret != 0)
    {
        return FAIL;
    }
    nistret = nist_ctr_drbg_reseed(&r->drbg,
                                   (const void *)&ei, ei_len,
                                   (const void *)ad, ad_len);
    if (nistret != 0)
    {
        return FAIL;
    }
    r->rbg_last_reseeded = r->rbg_bytes_output;
    return OK;
}

int drbg_reseed_ad(r)
    RBG *r;
{
    if (DRBG_STATUS != STATUS_OK)
    {
        return FAIL;
    }

    int nistret,ad_len,ei_len;
    uint8_t ei[48];
    ADATA *ad;
    ad = new_adata();
    ei_len = 48;
    ad_len = sizeof(*ad);
    nistret = nist_ctr_drbg_reseed(&r->drbg,
                                   (const void *)&ei, ei_len,
                                   (const void *)ad, ad_len);
    free_adata(ad);
    memset(&ei,0,ei_len);
    if (nistret != 0)
        return FAIL;
    r->rbg_last_reseeded = r->rbg_bytes_output;
    return OK;
}
