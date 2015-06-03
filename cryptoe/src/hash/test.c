#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bsd/string.h>
#include <errno.h>
#include <unistd.h>
#include "sha2.h"

#define SHA256_BUFSIZ (SHA256_DIGEST_SIZE * 2) + 1
static char hex_fmt[SHA256_DIGEST_SIZE*4] = "%02x%02x%02x%02x%02x%02x%02x%02x"
                                            "%02x%02x%02x%02x%02x%02x%02x%02x"
                                            "%02x%02x%02x%02x%02x%02x%02x%02x"
                                            "%02x%02x%02x%02x%02x%02x%02x%02x";

void hexdigest(unsigned char *digest, char *hex)
{   
    snprintf(hex,SHA256_BUFSIZ,hex_fmt,digest);
}

int
main(int argc,char **argv)
{
    unsigned char sha256_digest[SHA256_DIGEST_SIZE];
    unsigned char shad256_digest[SHA256_DIGEST_SIZE];
    char *msg;
    char dgst[129];
    unsigned int msg_len = 0;

    sha256_ctx ctx_256;
    sha256_ctx ctx_d256;

    if (argc != 2)
    {
        fprintf(stderr,"usage: %s <string to hash>\n",argv[0]);
        exit(0);
    }

    msg_len = strlen(argv[1]) + 1;
    msg = (char *)malloc(msg_len + 1);
    memset(msg,0,msg_len+1);
    if (msg == NULL)
    {
        fprintf(stderr,"malloc(%d) failed: %s\n",msg_len,strerror(errno));
        exit(0);
    }
    strlcpy(msg,argv[1],msg_len);
    printf("message: %s\n",msg);
    fflush(stdout);

    memset(&ctx_256,0,sizeof(sha256_ctx));
    memset(&ctx_d256,0,sizeof(sha256_ctx));

    sha256_init(&ctx_256);
    sha256_init(&ctx_d256);

    sha256_update(&ctx_256, (unsigned char *)msg, msg_len);
    sha256_update(&ctx_d256, (unsigned char *)msg, msg_len);

    sha256_final(&ctx_256, sha256_digest);
    sha256_final(&ctx_d256, shad256_digest);
    memset(&dgst,0,129);
    hexdigest(sha256_digest,dgst);
    printf("%p %p %lu %s\n",dgst,sha256_digest,strlen(dgst),dgst);
    memset(&dgst,0,129);

    hexdigest(shad256_digest,dgst);
    printf("%p %p %lu %s\n",dgst,shad256_digest,strlen(dgst),dgst);
    memset(&dgst,0,129);

/*    shad256_update(&ctx_d256, sha256_digest, SHA256_DIGEST_LEN); */

    memset(sha256_digest,0,SHA256_DIGEST_SIZE);
    memset(shad256_digest,0,SHA256_DIGEST_SIZE);
    memset(&ctx_256,0,sizeof(sha256_ctx));
    memset(&ctx_d256,0,sizeof(sha256_ctx));
    memset(msg,0,msg_len+1);
    free(msg);
    exit(0);
}

