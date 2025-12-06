#ifndef BITCOINFUZZ_CUSTOMMUTATOR_SECP256K1_SIGNATURE_H
#define BITCOINFUZZ_CUSTOMMUTATOR_SECP256K1_SIGNATURE_H

#include <custommutator/utils/signature.h>

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *fuzz_data, size_t size, size_t max_size,
										  unsigned int seed)
{
	// First, mutate the data using LibFuzzer's default mutator
	size_t new_size = LLVMFuzzerMutate(fuzz_data, size, max_size);

	// Then append ECDSA signature
	new_size = append_ecdsa_signature(fuzz_data, new_size);

	return new_size;
}

#endif // BITCOINFUZZ_CUSTOMMUTATOR_SECP256K1_SIGNATURE_H