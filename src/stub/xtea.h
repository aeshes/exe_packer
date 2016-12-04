#ifndef XTEA_H
#define XTEA_H

#include <stdint.h>

void DecryptBlock(unsigned int num_rounds, uint32_t *v, uint32_t const *k);

#endif