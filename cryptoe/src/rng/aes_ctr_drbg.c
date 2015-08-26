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
#include <sys/resource.h>
#include <fcntl.h>
#include <pthread.h>
#include <utmpx.h>

#include "rng/os_drbg.h"
#include "rng/nist_ctr_drbg.h"
#include "rng/drbg_api.h"
#include "RFC6234/sha.h"
#include "SHAd256.h"


#define HKDF_OP_LEN         64
#define HKDF_SALT_LEN       HKDF_OP_LEN
#define HKDF_IKM_LEN        HKDF_OP_LEN
#define HKDF_PRK_LEN        HKDF_OP_LEN
#define HKDF_INFO_LEN       64
#define HKDF_HASH           SHA512

#define DRBG_EI_LEN         48
#define DRBG_PS_LEN         48
#define DRBG_N1_LEN         8

#define HKDF_TRUNCATE(src,dest,len) \
    unsigned char ##dest[##len];

typedef struct hkdf_info {
    uint8_t         salt[HKDF_SALT_LEN];
    uint8_t         ikm[HKDF_IKM_LEN];
    uint8_t         prk[HKDF_PRK_LEN];
    unsigned char   info[HKDF_INFO_LEN];
} hkdf_info;
#if 0
static void
HKDF(salt,ikm,prk,okm,info,outlen)
    uint8_t *salt;
    uint8_t *ikm;
    unsigned char *info;
    uint8_t *okm;
    uint32_t outlen;
{
    hkdf
}
#endif
typedef struct ADATA {
    uint64_t    clk_mono;           /* monotonic clock */
    uint64_t    clk_real;           /* realtime clock */
    uint32_t    uid;                /* user id */
    uint32_t    gid;                /* group id */
    uint32_t    pid;                /* process id */
    uint32_t    ppid;               /* parent process id */
} ADATA;

#define AD_CLK_BITS         (64*2) /* 3 uint64_t's */
#define AD_XID_BITS         (32*4) /* 3 uint32_t's */
#define AD_SIZE             (AD_CLK_BITS + AD_XID_BITS) / 8

/* Get and clear Additional Data (as defined above) */
void collect(void *, int32_t);

static ADATA *new_adata(void);
static void free_adata(ADATA *);

/* get clock values */
static uint64_t clk_monotonic(void);
static uint64_t clk_realtime(void);

/* generate a key */
static int rbg_genkey(uint8_t *,uint32_t);

/* generate random data using CTR_DRBG */
static int rbg_generate(void *, uint8_t *, uint32_t);

/* allocate memory for a new RBG, and set the pointers */
#if 0
static RBG *rbg_alloc(void);
/* free the above */
static void rbg_destroy(void *);
/* Initialize */
static int init_drbg(NIST_CTR_DRBG *);
/* reseed */
static int rbg_reseed(void *);
#endif

/*
 * Generate a new key from the OS-provided CTR_DRBG
 * XOR the generated value with additional data that is computationally
 * separate from the value itself per SP800-133 section 5
 *
 * This is suitable for use at up to a 128 bit security strength.
 */
static int
rbg_genkey(seed,len)
    uint8_t *seed;
    uint32_t len;
{
    lhf();
    if (len > 64)
    {
        return -1;
    }

    uint8_t *rnd_in;
    uint8_t shabuf[64];
    sha2_state S2;
    SHAd256_init(&S2);
    SHAd256_update(&S2,(const uint8_t *)&ebuf,256);
    SHAd256_digest(&S2,(uint8_t *)&shabuf,16);
    collect(&shabuf,16);
    SHAd256_update(&S2,(const uint8_t *)&ebuf,256);
    SHAd256_digest(&S2,(uint8_t *)&shabuf+16,16);
    collect(&shabuf,16);
    SHAd256_update(&S2,(const uint8_t *)&ebuf,256);
    SHAd256_digest(&S2,(uint8_t *)&shabuf+16,16);
    SHAd256_update(&S2,(const uint8_t *)&ebuf,256);
    SHAd256_digest(&S2,(uint8_t *)&shabuf+16,16);

    collect(&shabuf,16);

    rnd_in = malloc(len);
    if (rnd_in == NULL)
        return -1;

    memset(rnd_in,0,len);
    if (read_os_drbg(rnd_in,len) == -1)
    {
        memset(rnd_in,0,len);
        free(rnd_in);
        return -1;
    }


    int i;

    for (i=0;i<64;i++)
    {
        seed[i] = rnd_in[i] ^ shabuf[i];
    }
    memset(&shabuf,0,256);
    memset(&S2,0,sizeof(S2));
    memset(rnd_in,0,len);
    free(rnd_in);
    return 0;
}

RBG *
new_rbg()
{
    RBG *r = rbg_alloc();
    NIST_CTR_DRBG *n = (NIST_CTR_DRBG *)&r->drbg;
    if (r == NULL)
    {
        return NULL;
    }
    int rv;

    rv = init_drbg(n);
    if (rv != 0)
    {
        fprintf(stderr,"init_drbg(%p) failed",n);
        rbg_destroy(r);
        return NULL;
    }
    if (rv != 0)
    {
        fprintf(stderr,"rbg_reseed(%p) failed\n",r);
        rbg_destroy(r);
        return NULL;
    }

    return r;
}

static int
init_drbg(d)
    NIST_CTR_DRBG   *d;
{
    int rv;
    lhf();
    rv = nist_ctr_initialize();
    if (rv != 0)
        return -1;

    uint64_t nonce;
    uint8_t ei[DRBG_EI_LEN];
    unsigned char ps[DRBG_PS_LEN];
    int ps_len = DRBG_PS_LEN;

    memset(&ei,0,DRBG_EI_LEN);
    memset(&ps,0,DRBG_PS_LEN);
    memset(&nonce,0,DRBG_N1_LEN);
//    nonce = clk_monotonic();

    rv = nist_ctr_drbg_instantiate(d,
                                   &ei, NIST_BLOCK_KEYLEN_BYTES,
                                   (const void *)&nonce, DRBG_N1_LEN,
                                   ps, ps_len);

    return rv;
}

static int
rbg_generate(ptr,buf,len)
    void *ptr;
    uint8_t *buf;
    uint32_t len;
{
    if (len > 524288)
    {
        return -1;
    }
    RBG *r = (RBG *)ptr;
    int rv;
    if ((r->rbg_bytes_output - r->rbg_last_reseeded) + len
        >= (NIST_CTR_DRBG_RESEED_INTERVAL/2))
    {
        rv = rbg_reseed(r);
        if (rv != 0)
        {
            return -1;
        }
    }

    ADATA *ad;
    ad = new_adata();
    rv = nist_ctr_drbg_generate(&r->drbg,
                                  (void *)buf, (int)len,
                                  (const void *)ad, sizeof(*ad));
    free_adata(ad);
    if (rv != 0)
    {
        return -1;
    }

    rbg_genkey(buf,len);

    r->rbg_bytes_output += len;
    return 0;
}

