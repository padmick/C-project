//sudocde from https://en.wikipedia.org/wiki/SHA-2 


#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <stdio.h>
#include "sha256.h"

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHR32(x, n) (x >> n)
#define ROR32(x, n) ((x >> n) | (x << (32 - n)))
#define SIGMA_UPPER_0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SIGMA_UPPER_1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIGMA_LOWER_0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ SHR32(x, 3))
#define SIGMA_LOWER_1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ SHR32(x, 10))

static void Sha256_ProcessBlock(sha256Context *context);


int main()
{
  sha256();
}



void Sha256_Init()
{

    context->h[0] = 0x6A09E667;
    context->h[1] = 0xBB67AE85;
    context->h[2] = 0x3C6EF372;
    context->h[3] = 0xA54FF53A;
    context->h[4] = 0x510E527F;
    context->h[5] = 0x9B05688C;
    context->h[6] = 0x1F83D9AB;
    context->h[7] = 0x5BE0CD19;
 

    context->size = 0;
    
    context->totalSize = 0;
}

// FIPS PUB 180-4 -- 5.3.3
//
// Initial hash value
// "These words were obtained by taking the first thirty-two bits of the fractional parts of the square
//  roots of the first eight prime numbers"


static const uint32_t k[64] =
{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};


static const uint8_t padding[64] =
{
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void Sha256_Compute()
{
    sha256Context Context;
    
    Sha256_Init(&Context);
    Sha256_Update(&Context, data, len);
    Sha256_Final(&Context, digest);
}


void Sha256_Update()
{
    while(len > 0)
        size_t n = MIN(len, 64 - context->size);
 
        memcpy(context->buffer + context->size, data, n);
 
        context->size += n;
        context->totalSize += n;
        
        data = (uint8_t *) data + n;
        len -= n;
 
        if(context->size == 64)
        {
            Sha256_ProcessBlock(context);
            context->size = 0;
        }
    }
}
void Sha256_Final()
 {
    // FIPS PUB 180-4 -- 5
    //
    // Padding:
    //
    // 5.1 Padding the Message
    // The purpose of this padding is to ensure that the padded message is a multiple of 512 or 1024
    // bits, depending on the algorithm. Padding can be inserted before hash computation begins on a
    // message, or at any other time during the hash computation prior to processing the block(s) that
    // will contain the padding
    //
    // 5.1.1 SHA-1, SHA-224 and SHA-256
 
    // Length of the original message before padding, in bits
    uint64_t l = context->totalSize * 8;
    size_t k = 0;
 
    if( l%512 < 448)
       k = 448 - l%512;
    else
       k = 512 + 448 - l%512;
 
    Sha256_Update(context, padding, k/8 /* k is a counter of bits */);
     context->w[14] = htobe32((uint32_t) (l >> 32));
    context->w[15] = htobe32((uint32_t) l);
 
    Sha256_ProcessBlock(context);
 
    for(size_t i = 0; i < 8; i++) context->h[i] = htobe32(context->h[i]);
 
    if(digest != NULL) memcpy(digest, context->digest, SHA256_DIGEST_SIZE);
 }


void Sha256_ProcessBlock()
{
    uint32_t w[64];     
 
  
    for(size_t t = 0 ; t <= 63 ; t++)
    {
        if( t<=15 )
            w[t] = betoh32(context->w[t]);
        else
            w[t] = SIGMA_LOWER_1(w[t-2]) + w[t-7] + SIGMA_LOWER_0(w[t-15]) + w[t-16];
    }

    uint32_t a = context->h[0];
    uint32_t b = context->h[1];
    uint32_t c = context->h[2];
    uint32_t d = context->h[3];
    uint32_t e = context->h[4];
    uint32_t f = context->h[5];
    uint32_t g = context->h[6];
    uint32_t h = context->h[7];
  

    for(size_t t = 0; t <= 63; t++)
    {
        

        uint32_t temp1 = h + SIGMA_UPPER_1(e) + CH(e, f, g) + k[t] + w[t];
        uint32_t temp2 = SIGMA_UPPER_0(a) + MAJ(a, b, c);
 
     
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
 
    context->h[0] += a;
    context->h[1] += b;
    context->h[2] += c;
    context->h[3] += d;
    context->h[4] += e;
    context->h[5] += f;
    context->h[6] += g;
    context->h[7] += h;
}
