#define __USE_BSD
#define _BSD_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <stdio.h>
#include "sha256.h"


// FIPS PUB 180-4 -- Figure 1
// Process 512 bite block
#define SHA256_BLOCK_SIZE (512/8)

// min function
#define MIN(a,b) (((a)<(b))?(a):(b))

// FIPS PUB 180-4 -- 4.1.2
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHR32(x, n) (x >> n)
#define ROR32(x, n) ((x >> n) | (x << (32 - n)))
#define EP0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define EP1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIG0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ SHR32(x, 3))
#define SIG1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ SHR32(x, 10))

static void Sha256_ProcessBlock(sha256Context *context);

// test on our SHA256 implementation
void main(void)
{
    unsigned char shaInput[3]={'a','b','c'};
    unsigned char shaOutput[SHA256_DIGEST_SIZE];


    Sha256_Calcuate(shaInput, sizeof(shaInput), shaOutput);
    printf("test output is %s",shaOutput);
	
	FILE *ptr_file;
    char buf[1000];

    ptr_file =fopen("input.txt","r");
    if (!ptr_file)
        return 1;

    while (fgets(buf,1000, ptr_file)!=NULL)
        printf("Text before Encription:  %s",buf);
	
	shaInput = buf;
	
	Sha256_Calcuate(shaInput, sizeof(shaInput), shaOutput);
    printf(" %s",shaOutput);
	

}

// FIPS PUB 180-4 -- 4.2.2
//
//Initialize array of round constants:
//(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
//k[0..63] :=
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

// FIPS PUB 180-4 -- 5.1 & 5.1.1
// To ensure data is multiple of 64 bytes
//Pre-processing (Padding):

static const uint8_t padding[64] =
{
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
 

void Sha256_Calcuate(const void *data, size_t len, uint8_t *digest)
{
    sha256Context Context;
    
    Sha256_Init(&Context);
    Sha256_Update(&Context, data, len);
    Sha256_Final(&Context, digest);
}

//
void Sha256_Init(sha256Context *context)
{
    // FIPS PUB 180-4 -- 5.3.3
    //
    // Initial hash value
    
   //Initialize hash values:
   //(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
   //h0 := 0x6a09e667
   //h1 := 0xbb67ae85
   //h2 := 0x3c6ef372
   //h3 := 0xa54ff53a
   //h4 := 0x510e527f
   //h5 := 0x9b05688c
   //h6 := 0x1f83d9ab
   //h7 := 0x5be0cd19

    context->h[0] = 0x6A09E667;
    context->h[1] = 0xBB67AE85;
    context->h[2] = 0x3C6EF372;
    context->h[3] = 0xA54FF53A;
    context->h[4] = 0x510E527F;
    context->h[5] = 0x9B05688C;
    context->h[6] = 0x1F83D9AB;
    context->h[7] = 0x5BE0CD19;
 
    // No bytes in the buffer
    context->size = 0;
    
    // No data was processed in the buffer so far
    context->totalSize = 0;
}
 
// This function accepts a partial message

//  context -> Pointer to the context structure that holds info needed to perform SHA25 on partial message.
//  data and len -> are the input buffer
//  digest -> to be populated with SHA256 result

void Sha256_Update(sha256Context *context, const void *data, size_t len)
{
    // Process the message
    while(len > 0)
    {
        // Calculate how many bytes to process at this pass
        size_t n = MIN(len, 64 - context->size);
 
        // Copy the data to the buffer
        memcpy(context->buffer + context->size, data, n);
 
        // Update context
        context->size += n;
        context->totalSize += n;
        
        // Update pointer into the message
        data = (uint8_t *) data + n;
        
        // Update remaining bytes to process
        len -= n;
 
        // Only process if the 64 bytes buffer is full
        if(context->size == 64)
        {
            // Process this block and empty the buffer
            Sha256_ProcessBlock(context);
            context->size = 0;
        }
    }
}
 


//  context -> Pointer to the context structure that holds info needed to perform SHA256 on partial message.
//  digest -> Points to a buffer to be populated with SHA256 result
 void Sha256_Final(sha256Context *context, uint8_t *digest)
 {
    // FIPS PUB 180-4 -- 5
    //
    // Padding:
    //
    // 5.1 Padding the Message
    // 5.1.1 SHA-1, SHA-224 and SHA-256
    //begin with the original message of length L bits
    //append a single '1' bit
    //append K '0' bits, where K is the minimum number >= 0 such that L + 1 + K + 64 is a multiple of 512
    //append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits

    // Length of the original message before padding, in bits
    uint64_t l = context->totalSize * 8;
    size_t k = 0;
 
    // Pad the message so that its length is congruent to 448 modulo 512
    if( l%512 < 448)
       k = 448 - l%512;
    else
       k = 512 + 448 - l%512;
    //Process the message in successive 512-bit chunks:
    ///break message into 512-bit chunks
    Sha256_Update(context, padding, k/8);
 
    // Final 64 bits
    context->w[14] = htobe32((uint32_t) (l >> 32));
    context->w[15] = htobe32((uint32_t) l);
    //Produce the final hash value (big-endian):
    //digest := hash := h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
    // Now the digest is calculated
    Sha256_ProcessBlock(context);
 
    // Convert from host byte order to big-endian byte order
    for(size_t i = 0; i < 8; i++) context->h[i] = htobe32(context->h[i]);
    
    // Copy the result to the user provided buffer
    if(digest != NULL) memcpy(digest, context->digest, SHA256_DIGEST_SIZE);
 }
 
 
// FIPS PUB 180-4 -- 6.2
//
// Process a block
//
void Sha256_ProcessBlock(sha256Context *context)
{   
    //for each chunk
    //create a 64-entry message schedule array w[0..63] of 32-bit words
    //(The initial values in w[0..63] don't matter, so many implementations zero them here)
    //copy chunk into first 16 words w[0..15] of the message schedule array
    uint32_t w[64];     // Message schedule
    //Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
    //for i from 16 to 63
    //    s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
    //    s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
    //    w[i] := w[i-16] + s0 + w[i-7] + s1
    for(size_t t = 0 ; t <= 63 ; t++)
    {
        if( t<=15 )
            w[t] = betoh32(context->w[t]);
        else
            w[t] = SIG1(w[t-2]) + w[t-7] + SIG0(w[t-15]) + w[t-16];
    }
    // Initialize working variables to current hash value:
    //a := h0
    //b := h1
    //c := h2
    //d := h3
    //e := h4
    //f := h5
    //g := h6
    //h := h7
    // 2. Initialize the eight working variables, a, b, c, d, e, f, g, and h,
    // with the (i-1)st hash value:
    uint32_t a = context->h[0];
    uint32_t b = context->h[1];
    uint32_t c = context->h[2];
    uint32_t d = context->h[3];
    uint32_t e = context->h[4];
    uint32_t f = context->h[5];
    uint32_t g = context->h[6];
    uint32_t h = context->h[7];
     //Compression function main loop:
    //for i from 0 to 63
      //  S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
      //  ch := (e and f) xor ((not e) and g)
      //  temp1 := h + S1 + ch + k[i] + w[i]
      //  S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
      //  maj := (a and b) xor (a and c) xor (b and c)
      //  temp2 := S0 + maj
 
        h := g
        g := f
        f := e
        e := d + temp1
        d := c
        c := b
        b := a
        a := temp1 + temp2

    // 3. Loop 64 times
    for(size_t t = 0; t <= 63; t++)
    {
        
        // Calculate T1 and T2
        uint32_t temp1 = h + EP1(e) + CH(e, f, g) + k[t] + w[t];
        uint32_t temp2 = EP0(a) + MAJ(a, b, c);
 
        // Update working registers
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    // Add the compressed chunk to the current hash value:
    //h0 := h0 + a
    //h1 := h1 + b
    //h2 := h2 + c
    //h3 := h3 + d
    //h4 := h4 + e
    //h5 := h5 + f
    //h6 := h6 + g
    //h7 := h7 + h
    // 4. Compute the ith intermediate hash value H(i):
    context->h[0] += a;
    context->h[1] += b;
    context->h[2] += c;
    context->h[3] += d;
    context->h[4] += e;
    context->h[5] += f;
    context->h[6] += g;
    context->h[7] += h;
}