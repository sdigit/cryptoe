#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "rdrand.h"

#define _rdrand_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })

#define __cpuid(x,y) asm volatile("cpuid":"=a"(x[0]),"=b"(x[1]),"=c"(x[2]),"=d"(x[3]):"a"(y))

int RdRand_cpuid()
{
	int info[4] = {-1, -1, -1, -1};

	/* Are we on an Intel processor? */
	__cpuid(info, 0);
	if (memcmp((void *) &info[1], (void *) "Genu", 4) != 0 ||
		memcmp((void *) &info[3], (void *) "ineI", 4) != 0 ||
		memcmp((void *) &info[2], (void *) "ntel", 4) != 0 ) {

		return 0;
	}

	 __cpuid(info, /*feature bits*/1);
	 int ecx = info[2];

	/* Do we have RDRAND? */
	 if ((ecx & RDRAND_MASK) == RDRAND_MASK)
		 return 1;
	 else
		 return 0;
}

int RdRand_isSupported()
{
	static int supported = RDRAND_SUPPORT_UNKNOWN;

	if (supported == RDRAND_SUPPORT_UNKNOWN)
	{
		if (RdRand_cpuid())
			supported = RDRAND_SUPPORTED;
		else
			supported = RDRAND_UNSUPPORTED;
	}
	return (supported == RDRAND_SUPPORTED) ? 1 : 0;
}

int rdrand_64(uint64_t* x, int retry)
{
    if (retry)
    {
        int i;
        for (i= 0; i < RETRY_LIMIT; i++)
        {
            if (_rdrand_step(x))
                return RDRAND_SUCCESS;
        }
        return RDRAND_NOT_READY;
    }
    else
    {
        if (_rdrand_step(x))
            return RDRAND_SUCCESS;
        else
            return RDRAND_NOT_READY;
    }
}


int rdrand_get_n_64(unsigned int n, uint64_t *dest)
{
    int ret;
    int count;
    unsigned int i;

    for (i=0; i<n; i++)
    {
        count = 0;
        do
        {
            ret = rdrand_64(dest, 1);
            count++;
        } while((ret == RDRAND_NOT_READY) && (count < RETRY_LIMIT));

        if (ret != RDRAND_SUCCESS)
        {
            memset(dest,0,n);
            return ret;
        }
        dest = &(dest[1]);
    }
    return RDRAND_SUCCESS;
}

int rdrand_get_bytes(unsigned int n, unsigned char *dest)
{
    unsigned char *start;
    unsigned char *residualstart;
    uint64_t *blockstart;
    uint64_t i, temprand;
    unsigned int count;
    unsigned int residual;
    unsigned int startlen;
    unsigned int length;
    int ret;

    temprand = 0;
    start = dest;
    if (( (uint64_t)start % sizeof(uint64_t)) == 0)
    {
        blockstart = (uint64_t *)start;
        count = n;
        startlen = 0;

    }
    else
    {
        blockstart = (uint64_t *)(((uint64_t)start & ~(sizeof(uint64_t)-1))+sizeof(uint64_t));
        count = n - (sizeof(uint64_t) - (unsigned int)((uint64_t)start % sizeof(uint64_t)));
        startlen = (unsigned int)((uint64_t)&blockstart - (uint64_t)start);
    }

    /* Compute the number of blocks and the remaining number of bytes */
    residual = count % sizeof(uint64_t);
    length = count/sizeof(uint64_t);
    if (residual != 0)
        residualstart = (unsigned char *)(blockstart + length);

    /* Get a temporary random number for use in the residuals. Failout if retry fails */
    if (startlen > 0)
    {
        if ( (ret= rdrand_64((uint64_t *) &temprand, 1)) != RDRAND_SUCCESS)
            return ret;
    }

    /* populate the starting misaligned block */
    for (i = 0; i<startlen; i++)
    {
        start[i] = (unsigned char)(temprand & 0xff);
        temprand = temprand >> 8;
    }
    if (startlen > 0)
        temprand = 0;
    /* populate the central aligned block. Fail out if retry fails */

    if ( (ret= rdrand_get_n_64(length, (uint64_t *)(blockstart))) != RDRAND_SUCCESS)
        return ret;
    /* populate the final misaligned block */
    if (residual > 0)
    {
        if ((ret= rdrand_64((uint64_t *)&temprand, 1)) != RDRAND_SUCCESS) return ret;
        for (i = 0; i<residual; i++)
        {
            residualstart[i] = (unsigned char)(temprand & 0xff);
            temprand = temprand >> 8;
        }
        temprand = 0;
    }
    return RDRAND_SUCCESS;
}

