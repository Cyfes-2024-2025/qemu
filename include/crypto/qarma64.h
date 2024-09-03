#ifndef QARMA64_H
#define QARMA64_H

#include <stdio.h>
#include <stdint.h>

uint64_t qarma64_dec(uint64_t plaintext, uint64_t tweak, uint64_t w0, uint64_t k0, int rounds);
uint64_t qarma64_enc(uint64_t plaintext, uint64_t tweak, uint64_t w0, uint64_t k0, int rounds);

#endif // QARMA64_H
