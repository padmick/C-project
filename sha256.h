#ifndef _SHA256_H
#define _SHA256_H
 
#include <stdint.h>

// FIPS PUB 180-4 -- Figure 1
// SHA256 outputs 256 bits digest
#define SHA256_DIGEST_SIZE (256/8)