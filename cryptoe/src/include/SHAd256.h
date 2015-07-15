#ifndef SHAD256_H
# define SHAD256_H
#include <stdint.h>
#include <inttypes.h>
/*
#ifdef __linux__
# define USE_PRCTL
#endif
*/
#define DIGEST_SIZE         32
#define BLOCK_SIZE          64
#define WORD_SIZE           4
#define SCHEDULE_SIZE       64

#define BLOCK_SIZE_BITS     (BLOCK_SIZE*8)
#define DIGEST_SIZE_BITS    (DIGEST_SIZE*8)
#define WORD_SIZE_BITS      (WORD_SIZE*8)

/* define some helper macros */
#define PADDING_SIZE        (2 * WORD_SIZE)
#define LAST_BLOCK_SIZE     (BLOCK_SIZE - PADDING_SIZE)

/* define generic SHA-2 family functions */
#define Ch(x,y,z)   ((x & y) ^ (~x & z))
#define Maj(x,y,z)  ((x & y) ^ (x & z) ^ (y & z))
#define ROTR(x, n)  (((x)>>((n)&(WORD_SIZE_BITS-1)))|((x)<<(WORD_SIZE_BITS-((n)&(WORD_SIZE_BITS-1)))))
#define SHR(x, n)   ((x)>>(n))

typedef struct{
    uint32_t state[8];
    int curlen;
    uint32_t length_upper, length_lower;
    unsigned char buf[BLOCK_SIZE];
} sha2_state;

void SHAd256_init (sha2_state *);
void SHAd256_update (sha2_state *,const uint8_t *,int);
void SHAd256_digest(sha2_state *, uint8_t *,int);

#endif /* SHAD256_H */

