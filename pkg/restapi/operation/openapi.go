/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "github.com/trustbloc/edv/pkg/restapi/models"

// TODO: Swagger UI doesn't show location header in response: #89
// TODO: Standardize response body messages to always be in JSON format: #90

// genericError model
//
// swagger:response genericError
type genericError struct { // nolint: unused,deadcode
	// in: body
	ErrMsg string
}

// createVaultReq model
//
// swagger:parameters createVaultReq
type createVaultReq struct { // nolint: unused,deadcode
	// in: body
	NewVaultRequest models.DataVaultConfiguration
}

// createVaultRes model
//
// swagger:response createVaultRes
type createVaultRes struct { // nolint: unused,deadcode
	Location string
}

// queryVaultReq model
//
// swagger:parameters queryVaultReq
type queryVaultReq struct { // nolint: unused,deadcode
	// in: path
	// required: true
	VaultID string `json:"vaultID"`
	// in: body
	QueryRequest models.Query
}

// TODO: See if this can be updated to be a json array, since that's what the output actually is. #90

// queryVaultRes model
//
// swagger:response queryVaultRes
type queryVaultRes struct { // nolint: unused,deadcode
	// in: body
	QueryResults string
}

// createDocumentReq model
//
// swagger:parameters createDocumentReq
type createDocumentReq struct { // nolint: unused,deadcode
	// in: path
	// required: true
	VaultID string `json:"vaultID"`
	// in: body
	NewDocument models.StructuredDocument
}

// createDocumentRes model
//
// swagger:response createDocumentRes
type createDocumentRes struct { // nolint: unused,deadcode
	Location string
}

// readDocumentReq model
//
// swagger:parameters readDocumentReq
type readDocumentReq struct { // nolint: unused,deadcode
	// in: path
	// required: true
	VaultID string `json:"vaultID"`
	// in: path
	// required: true
	DocID string `json:"docID"`
}

// readDocumentRes model
//
// swagger:response readDocumentRes
type readDocumentRes struct { // nolint: unused,deadcode
	// in: body
	RetrievedDocument string
}

// updateDocumentReq model
//
// swagger:parameters updateDocumentReq
type updateDocumentReq struct { // nolint: unused,deadcode
	// in: path
	// required: true
	VaultID string `json:"vaultID"`
	// in: path
	// required: true
	DocID string `json:"docID"`
	// in: body
	Document models.EncryptedDocument
}

// deleteDocumentReq model
//
// swagger:parameters deleteDocumentReq
type deleteDocumentReq struct { // nolint: unused,deadcode
	// in: path
	// required: true
	VaultID string `json:"vaultID"`
	// in: path
	// required: true
	DocID string `json:"docID"`
}

// emptyRes model
//
// swagger:response emptyRes
type emptyRes struct { // nolint: unused,deadcode
}
