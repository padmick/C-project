#ifndef _SHA256_H
#define _SHA256_H
 
#include <stdint.h>
#define SHA256_DIGEST_SIZE (256/8)

void Sha256_Init(sha256Context *context);
