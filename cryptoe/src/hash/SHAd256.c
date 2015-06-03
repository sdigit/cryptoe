#include <string.h>
#include <inttypes.h>

#include "sha2.h"

void shad256_update(sha256_ctx *ctx, const unsigned char *message,
                    unsigned int len)
{
    static unsigned int block_nb;
    static unsigned int new_len, rem_len, tmp_len;
    static unsigned char zero_block[SHA256_BLOCK_SIZE];
    const unsigned char *shifted_message;


    memset(zero_block,0,SHA256_BLOCK_SIZE);

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->block, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 6],
           rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

