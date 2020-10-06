/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvutils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edv/pkg/restapi/messages"
)

const (
	testBase58encoded128bitString = "Sr7yHjomhn1aeaFnxREfRN"
	testConvertedUUIDString       = "d15034fa-9525-4ebf-3352-d19c8b02cf05"

	not128BitString = "testString"
)

func Test_GenerateEDVCompatibleID(t *testing.T) {
	id, err := GenerateEDVCompatibleID()
	require.NoError(t, err)
	require.NotEmpty(t, id)
}

func Test_generateEDVCompatibleID_Failure(t *testing.T) {
	t.Run("Failure while generating random bytes", func(t *testing.T) {
		id, err := generateEDVCompatibleID(failingGenerateRandomBytesFunc)
		require.EqualError(t, err, errRandomByteGeneration.Error())
		require.Empty(t, id)
	})
}

func TestCheckIfBase58Encoded128BitValue(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		err := CheckIfBase58Encoded128BitValue(testBase58encoded128bitString)
		require.NoError(t, err)
	})
	t.Run("Failure - not base58 encoded", func(t *testing.T) {
		err := CheckIfBase58Encoded128BitValue("")
		require.Equal(t, messages.ErrNotBase58Encoded, err)
	})
	t.Run("Failure - not 128 bit", func(t *testing.T) {
		err := CheckIfBase58Encoded128BitValue(not128BitString)
		require.Equal(t, messages.ErrNot128BitValue, err)
	})
}

func TestBase58Encoded128BitToUUID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		uuidString, err := Base58Encoded128BitToUUID(testBase58encoded128bitString)
		require.NoError(t, err)
		require.Equal(t, testConvertedUUIDString, uuidString)
	})
}

var errRandomByteGeneration = errors.New("failingGenerateRandomBytesFunc always fails")

func failingGenerateRandomBytesFunc(_ []byte) (int, error) {
	return -1, errRandomByteGeneration
}
