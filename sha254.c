#include <stdio.h>

#include <stdlib.h>
#include <stdint.h>
#include <string.h>


int main()
{
  sha256();
}

sha256(){

//sudocde from https://en.wikipedia.org/wiki/SHA-2 
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

// FIPS PUB 180-4 -- 5.3.3
//
// Initial hash value
// "These words were obtained by taking the first thirty-two bits of the fractional parts of the square
//  roots of the first eight prime numbers"
h[0] = 0x6A09E667;
h[1] = 0xBB67AE85;
h[2] = 0x3C6EF372;
h[3] = 0xA54FF53A;
h[4] = 0x510E527F;
h[5] = 0x9B05688C;
h[6] = 0x1F83D9AB;
h[7] = 0x5BE0CD19;


}