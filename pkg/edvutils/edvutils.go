/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvutils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/btcsuite/btcutil/base58"

	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	jweAlgField = "alg"
	none        = "none"
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
	const number16 = 16

	decodedBytes := base58.Decode(id)
	if len(decodedBytes) == 0 {
		return messages.ErrNotBase58Encoded
	}

	if len(decodedBytes) != number16 {
		return messages.ErrNot128BitValue
	}

	return nil
}

// CheckIfURI checks if the given string is a valid URI.
func CheckIfURI(str string) error {
	_, err := url.ParseRequestURI(str)
	if err != nil {
		return fmt.Errorf(messages.InvalidURI, str)
	}

	return nil
}

// CheckIfArrayIsURI checks if every string in the given string array is a valid URI.
func CheckIfArrayIsURI(arr []string) error {
	for _, str := range arr {
		if err := CheckIfURI(str); err != nil {
			return err
		}
	}

	return nil
}

// ValidateJWE returns an error if the given raw JWE is empty or has invalid alg fields.
func ValidateJWE(rawJWE []byte) error {
	if len(rawJWE) == 0 {
		return errors.New(messages.BlankJWE)
	}

	jwe := models.JSONWebEncryption{}
	if err := json.Unmarshal(rawJWE, &jwe); err != nil {
		return err
	}

	return checkAlg(&jwe)
}

func checkAlg(jwe *models.JSONWebEncryption) error {
	if jwe.B64ProtectedHeaders != "" {
		foundAlg, err := checkAlgInProtectedHeader(jwe.B64ProtectedHeaders)
		if err != nil {
			return err
		}

		if foundAlg {
			return nil
		}
	}

	if jwe.SingleRecipientHeader != nil && jwe.SingleRecipientHeader.Alg != "" &&
		jwe.SingleRecipientHeader.Alg != none {
		return nil
	}

	if jwe.Recipients != nil {
		return checkJWERecipientsHeaders(jwe.Recipients)
	}

	return errors.New(messages.BlankJWEAlg)
}

// checkAlgInProtectedHeader base-64 decodes the protected headers string and returns true if 'alg' exists.
func checkAlgInProtectedHeader(b64Protected string) (bool, error) {
	decodedProtectedHeadersBytes, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(b64Protected)
	if err != nil {
		return false, errors.New(messages.Base64DecodeJWEProtectedHeadersFailure)
	}

	var decodedProtectedHeaders map[string]interface{}

	err = json.Unmarshal(decodedProtectedHeadersBytes, &decodedProtectedHeaders)
	if err != nil {
		return false, errors.New(messages.BadJWEProtectedHeaders)
	}

	if val, ok := decodedProtectedHeaders[jweAlgField]; ok {
		if val != none {
			return true, nil
		}
	}

	return false, nil
}

// checkJWERecipientsHeaders checks if all recipients in the recipient array have valid 'alg' fields.
func checkJWERecipientsHeaders(recipients []models.Recipient) error {
	for _, recipient := range recipients {
		if recipient.Header == nil || recipient.Header.Alg == "" || recipient.Header.Alg == none {
			return errors.New(messages.BlankJWEAlg)
		}
	}

	return nil
}
