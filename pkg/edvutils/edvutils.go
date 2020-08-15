/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvutils

import (
	"crypto/rand"

	"github.com/btcsuite/btcutil/base58"
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
