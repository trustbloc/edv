/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvutils

import (
	"crypto/rand"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"

	"github.com/trustbloc/edv/pkg/restapi/messages"
)

type generateRandomBytesFunc func([]byte) (int, error)

// GenerateEDVCompatibleID generates an EDV compatible ID using a cryptographically secure random number generator.
func GenerateEDVCompatibleID() (string, error) {
	return generateEDVCompatibleID(rand.Read)
}

func generateEDVCompatibleID(generateRandomBytes generateRandomBytesFunc) (string, error) {
	randomBytes := make([]byte, 16)

	_, err := generateRandomBytes(randomBytes)
	if err != nil {
		return "", err
	}

	base58EncodedUUID := base58.Encode(randomBytes)

	return base58EncodedUUID, nil
}

// CheckIfBase58Encoded128BitValue can't tell if the value before being encoded was precisely 128 bits long.
// This is because the byte58.decode function returns an array of bytes, not just a string of bits.
// So the closest I can do is see if the decoded byte array is 16 bytes long,
// however this means that if the original value was 121 bits to 127 bits long it'll still be accepted.
func CheckIfBase58Encoded128BitValue(id string) error {
	decodedBytes := base58.Decode(id)
	if len(decodedBytes) == 0 {
		return messages.ErrNotBase58Encoded
	}

	if len(decodedBytes) != 16 {
		return messages.ErrNot128BitValue
	}

	return nil
}

// Base58Encoded128BitToUUID decodes the given string and creates a uuid from the bytes array.
func Base58Encoded128BitToUUID(name string) (string, error) {
	decodedBytes := base58.Decode(name)

	storeNameUUID, err := uuid.FromBytes(decodedBytes)
	if err != nil {
		return "", nil
	}

	return storeNameUUID.String(), nil
}
