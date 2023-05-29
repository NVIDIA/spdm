#include "random.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h> /* exit */

static FILE* frand;

//! Initialize random generator
int random_init(void)
{
    frand = fopen("/dev/urandom", "r");
    if(!frand) {
        return -1;
    }
    return 0;
}

//! Get random value
int random_value(u32* val)
{
    if(frand) {
        unsigned ret = fread(val, sizeof(*val), 1, frand);
        if(ret==1) {
            return 0;
        }
        return -1;
    }
    return -1;
}

//! Deinitialize random gen
void random_deinit(void)
{
    if(frand) {
        fclose(frand);
    }
}

