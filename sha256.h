#ifndef _SHA256_H
#define _SHA256_H
 
#include <stdint.h>

// FIPS PUB 180-4 -- Figure 1
// SHA256 outputs 256 bits digest
#define SHA256_DIGEST_SIZE (256/8)
 
// A context is needed in order to allow processing pieces of data
//  
typedef struct
{
    union
    {
        uint32_t    h[SHA256_DIGEST_SIZE/4];
        uint8_t     digest[SHA256_DIGEST_SIZE];
    };
    
    union
    {
       uint32_t     w[16];
       uint8_t buffer[64];
    };
    
    size_t size;
    
    // Total Number of bytes processed so far.
    uint64_t totalSize;
} sha256Context;
 
// SHA256 functions
void Sha256_Calcuate(const void *data, size_t length, uint8_t *digest);
void Sha256_Init(sha256Context *context);
void Sha256_Update(sha256Context *context, const void *data, size_t length);
void Sha256_Final(sha256Context *context, uint8_t *digest);
 
#endif