#include <sys/param.h>
#include <sys/sysctl.h>
#include <inttypes.h>
#include "ctapi.h"

int
read_ctr_drbg(buf,len)
    uint8_t *buf;
    size_t len;
{
    int mib[2] = {CTL_KERN, KERN_ARND};
    return sysctl(mib,2,buf,&len,NULL,0);
}
