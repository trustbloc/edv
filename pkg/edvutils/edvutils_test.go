/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvutils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
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

var errRandomByteGeneration = errors.New("failingGenerateRandomBytesFunc always fails")

func failingGenerateRandomBytesFunc(_ []byte) (int, error) {
	return -1, errRandomByteGeneration
}
