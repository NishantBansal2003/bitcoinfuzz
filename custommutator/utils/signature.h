#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <span>
#include <cstdint>

size_t append_ecdsa_signature(uint8_t *data, size_t size);

#endif // SIGNATURE_H
