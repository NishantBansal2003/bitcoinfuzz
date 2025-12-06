package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    char* data;
    int length;
} ByteArray;
*/
import "C"
import (
	"crypto/sha256"
	"encoding/hex"
	"unsafe"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

//export DecredPrivateToPublicKey
func DecredPrivateToPublicKey(privKeyData C.ByteArray) *C.char {
	privKeyBytes := C.GoBytes(unsafe.Pointer(privKeyData.data), privKeyData.length)

	privKey := secp.PrivKeyFromBytes(privKeyBytes)
	pubKeyBytes := privKey.PubKey().SerializeCompressed()
	pubKeyStr := hex.EncodeToString(pubKeyBytes)

	return C.CString(pubKeyStr)
}

// NormalizeHashToCurveOrder reduces a hash modulo the secp256k1 curve order.
// This ensures compatibility with libsecp256k1's behavior, which automatically
// performs modular reduction on message hashes before deterministic nonce generation.
//
// While signatures produced from unreduced hashes are still cryptographically
// valid and compliant with RFC 6979 section 3.6, this normalization ensures
// deterministic signature matching across libsecp256k1 implementation.
func NormalizeHashToCurveOrder(hashBytes []byte) []byte {
	var scalar secp256k1.ModNScalar
	scalar.SetByteSlice(hashBytes)
	hash := scalar.Bytes()
	return hash[:]
}

//export DecredSignCompact
func DecredSignCompact(privKeyData C.ByteArray, hashData C.ByteArray) *C.char {
	privKeyBytes := C.GoBytes(unsafe.Pointer(privKeyData.data), privKeyData.length)
	hashBytes := C.GoBytes(unsafe.Pointer(hashData.data), hashData.length)

	privKey := secp.PrivKeyFromBytes(privKeyBytes)
	hashBytesMod := NormalizeHashToCurveOrder(hashBytes)
	sign := ecdsa.SignCompact(privKey, hashBytesMod, false)
	signStr := hex.EncodeToString(sign[1:])

	return C.CString(signStr)
}

//export DecredSignDER
func DecredSignDER(privKeyData C.ByteArray, hashData C.ByteArray) *C.char {
	privKeyBytes := C.GoBytes(unsafe.Pointer(privKeyData.data), privKeyData.length)
	hashBytes := C.GoBytes(unsafe.Pointer(hashData.data), hashData.length)

	privKey := secp.PrivKeyFromBytes(privKeyBytes)
	hashBytesMod := NormalizeHashToCurveOrder(hashBytes)
	sign := ecdsa.Sign(privKey, hashBytesMod).Serialize()
	signStr := hex.EncodeToString(sign)

	return C.CString(signStr)
}

//export DecredSignVerify
func DecredSignVerify(privKeyData C.ByteArray, hashData C.ByteArray, signData C.ByteArray) C.int {
	privKeyBytes := C.GoBytes(unsafe.Pointer(privKeyData.data), privKeyData.length)
	hashBytes := C.GoBytes(unsafe.Pointer(hashData.data), hashData.length)
	signBytes := C.GoBytes(unsafe.Pointer(signData.data), signData.length)

	privKey := secp.PrivKeyFromBytes(privKeyBytes)
	sign, err := ecdsa.ParseDERSignature(signBytes)
	if err != nil {
		return 0
	}

	if sign.Verify(hashBytes, privKey.PubKey()) {
		return 1
	}

	return 0
}

//export DecredECDH
func DecredECDH(privKeyData C.ByteArray) *C.char {
	var (
		pubJacobian secp.JacobianPoint
		s           secp.JacobianPoint
	)

	privKeyBytes := C.GoBytes(unsafe.Pointer(privKeyData.data), privKeyData.length)

	privKey := secp.PrivKeyFromBytes(privKeyBytes)
	pubKey := privKey.PubKey()
	pubKey.AsJacobian(&pubJacobian)

	secp.ScalarMultNonConst(&privKey.Key, &pubJacobian, &s)
	s.ToAffine()
	sPubKey := secp.NewPublicKey(&s.X, &s.Y)
	secret := sha256.Sum256(sPubKey.SerializeCompressed())
	secretStr := hex.EncodeToString(secret[:])

	return C.CString(secretStr)
}

func main() {}
