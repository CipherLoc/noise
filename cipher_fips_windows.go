//go:build fips
// +build fips

package noise

/*
#cgo LDFLAGS: -L ./libs -llibpec
#cgo LDFLAGS: -L ./libs -llibeay32
#cgo LDFLAGS: -L ./libs -lssleay32
#cgo CFLAGS: -I ./include/
#include <Engine_EX.h>
*/
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"unsafe"
)

// CipherAESGCM is the AES256-GCM AEAD cipher.
var CipherAESGCMFIPS CipherFunc = cipherFn{cipherAESGCMFIPS, "AESGCM"}

func cipherAESGCMFIPS(k [32]byte) Cipher {
	c, err := aes.NewCipher(k[:])
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)
	}

	return aeadCipher{
		gcm,
		func(n uint64) []byte {
			var nonce [12]byte
			binary.BigEndian.PutUint64(nonce[4:], n)
			return nonce[:]
		},
		k,
		"AESGCMFIPS",
	}
}

func EncryptPEC(key string, input []byte) []byte {
	// BRIDGE GO VARS TO C VARS
	pKey := (*C.uchar)(unsafe.Pointer(C.CString(key)))
	keyLength := C.uint64_t(len(key))
	pInput := (*C.uchar)(unsafe.Pointer(&input[0]))
	inputLength := C.uint64_t(len(input))
	outputArray := make([]byte, 8096)
	outputLength := C.uint64_t(0)
	pOutput := (*C.uchar)(unsafe.Pointer(&outputArray[0]))
	pOutputLength := (*C.uint64_t)(unsafe.Pointer(&outputLength))

	C.EncryptText_GO(pKey, keyLength, pInput, inputLength, pOutput, pOutputLength)

	// TRIM ARRAY
	return outputArray[0:outputLength]
}

func DecryptPEC(key string, input []byte) []byte {
	// BRIDGE GO VARS TO C VARS
	pKey := (*C.uchar)(unsafe.Pointer(C.CString(key)))
	keyLength := C.uint64_t(len(key))
	pInput := (*C.uchar)(unsafe.Pointer(&input[0]))
	inputLength := C.uint64_t(len(input))
	outputArray := make([]byte, 8096)
	outputLength := C.uint64_t(0)
	pOutput := (*C.uchar)(unsafe.Pointer(&outputArray[0]))
	pOutputLength := (*C.uint64_t)(unsafe.Pointer(&outputLength))

	C.DecryptText_GO(pKey, keyLength, pInput, inputLength, pOutput, pOutputLength)

	// TRIM ARRAY
	return outputArray[0:outputLength]
}

func (c aeadCipher) Key() [32]byte { return c.key }

func (c aeadCipher) Name() string { return c.name }

func (c aeadCipher) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {

	ciphertext := c.Seal(out, c.nonce(n), plaintext, ad)

	// ONLY HAPPENS WHEN ENCRYTPING KEYS
	if len(ad) > 0 {
		return ciphertext
	}

	// ENCRYPT FIPS
	if len(ciphertext) > 0 && c.name == "AESGCMFIPS" {
		var k [32]byte = c.Key()
		var key string = string(k[:])

		output := EncryptPEC(string(key), ciphertext)
		return output
	}

	return ciphertext
}

func (c aeadCipher) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	var output = ciphertext

	// DECRYPT FIPS
	if len(ad) == 0 && len(ciphertext) > 0 && c.name == "AESGCMFIPS" {
		var k [32]byte = c.Key()
		var key string = string(k[:])

		output = DecryptPEC(key, ciphertext)
	}

	plaintext, err := c.Open(out, c.nonce(n), output, ad)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return plaintext, err
	}

	return plaintext, nil
}
