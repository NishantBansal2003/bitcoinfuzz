#define template c_template // avoid C++ keyword conflict just during includes

extern "C"
{
#include <secp256k1.h>
}

#undef template

#include <cstddef>
#include <cstring>
#include <signature.h>

static constexpr size_t MIN_BUFFER_SIZE = 64;

// Append ECDSA signature in DER format
size_t append_ecdsa_signature(uint8_t *data, size_t size)
{
	if (size < MIN_BUFFER_SIZE)
	{
		return size;
	}

	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (!ctx)
	{
		return size;
	}

	secp256k1_ecdsa_signature signature;
	size_t signature_der_len = 74;
	unsigned char signature_der[signature_der_len];
	int ret = 0;

	// Extract first 64 bytes for private key and hash
	std::span<const uint8_t> buffer(data, 64);
	std::span<const uint8_t> privkey = buffer.subspan(0, 32);
	std::span<const uint8_t> hash = buffer.subspan(32, 32);

	// Verify private key
	ret = secp256k1_ec_seckey_verify(ctx, privkey.data());
	// Sign the hash
	ret = ret && secp256k1_ecdsa_sign(ctx, &signature, hash.data(), privkey.data(), nullptr, nullptr);
	// Serialize to DER format
	ret = ret && secp256k1_ecdsa_signature_serialize_der(ctx, signature_der, &signature_der_len, &signature);

	secp256k1_context_destroy(ctx);

	if (!ret)
	{
		return size;
	}

	// Append signature after first 64 bytes
	memcpy(data + MIN_BUFFER_SIZE, signature_der, signature_der_len);
	return MIN_BUFFER_SIZE + signature_der_len;
}
