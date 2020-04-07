/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memedvprovider

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewProvider(t *testing.T) {
	prov := NewProvider()
	require.NotNil(t, prov)
}
