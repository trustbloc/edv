/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edv/pkg/edvprovider/memedvprovider"
	"github.com/trustbloc/edv/pkg/restapi/operation"
)

func TestController_New(t *testing.T) {
	controller, err := New(&operation.Config{Provider: memedvprovider.NewProvider()})
	require.NoError(t, err)
	require.NotNil(t, controller)
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New(&operation.Config{Provider: memedvprovider.NewProvider(),
		EnabledExtensions: &operation.EnabledExtensions{ReadAllDocumentsEndpoint: true}})
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()

	require.Equal(t, 7, len(ops))

	// Create vault
	require.Equal(t, "/encrypted-data-vaults", ops[0].Path())
	require.Equal(t, http.MethodPost, ops[0].Method())
	require.NotNil(t, ops[0].Handle())

	// Query vault
	require.Equal(t, "/encrypted-data-vaults/{vaultID}/query", ops[1].Path())
	require.Equal(t, http.MethodPost, ops[1].Method())
	require.NotNil(t, ops[1].Handle())

	// Create document
	require.Equal(t, "/encrypted-data-vaults/{vaultID}/documents", ops[2].Path())
	require.Equal(t, http.MethodPost, ops[2].Method())
	require.NotNil(t, ops[2].Handle())

	// Read document
	require.Equal(t, "/encrypted-data-vaults/{vaultID}/documents/{docID}", ops[3].Path())
	require.Equal(t, http.MethodGet, ops[3].Method())
	require.NotNil(t, ops[3].Handle())

	// Update document
	require.Equal(t, "/encrypted-data-vaults/{vaultID}/documents/{docID}", ops[4].Path())
	require.Equal(t, http.MethodPost, ops[4].Method())
	require.NotNil(t, ops[4].Handle())

	// Delete document
	require.Equal(t, "/encrypted-data-vaults/{vaultID}/documents/{docID}", ops[5].Path())
	require.Equal(t, http.MethodDelete, ops[5].Method())
	require.NotNil(t, ops[5].Handle())

	// Read all documents
	require.Equal(t, "/encrypted-data-vaults/{vaultID}/documents", ops[6].Path())
	require.Equal(t, http.MethodGet, ops[6].Method())
	require.NotNil(t, ops[6].Handle())
}
