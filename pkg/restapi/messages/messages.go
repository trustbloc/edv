/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messages

const (
	// ErrVaultNotFound is used when a vault could not be found in the provider.
	ErrVaultNotFound = edvError("specified vault does not exist")
	// ErrDocumentNotFound is used when a document could not be found in a vault.
	ErrDocumentNotFound = edvError("specified document does not exist")
	// ErrDuplicateVault is used when an attempt is made to create a vault under a name that is already being used.
	ErrDuplicateVault = edvError("vault already exists")
	// ErrDuplicateDocument is used when an attempt is made to create a document with an ID that is already being used.
	ErrDuplicateDocument = edvError("a document with the given ID already exists")
	// ErrNotBase58Encoded is the error returned by the EDV server when an attempt is made
	// to create a document with an ID that is not a base58-encoded value (which is required by the EDV spec).
	ErrNotBase58Encoded = edvError("document ID must be a base58-encoded value")
	// ErrNot128BitValue is the error returned by the EDV server when an attempt is made
	// to create a document with an ID that is base58-encoded, but the original value was not 128 bits long
	// (which is required by the EDV spec).
	ErrNot128BitValue = edvError("document ID is base58-encoded, but original value before encoding was not 128 bits long")

	// FailWriteResponse is logged when a ResponseWriter fails to write.
	FailWriteResponse = ` Failed to write response back to sender: %s.`

	// CreateVaultFailReadResponseBody is used when the incoming request body can't be read..
	// This should not happen during normal operation.
	CreateVaultFailReadResponseBody = "Received request to create a new data vault, " +
		"but failed to read the request body: %s."

	// InvalidVaultConfig is used when a received data vault configuration is invalid.
	InvalidVaultConfig = "Received invalid data vault configuration: %s."
	// BlankReferenceID is the message returned by the EDV server when an attempt is made to create a vault
	// with a blank reference ID.
	BlankReferenceID = "referenceId can't be blank"
	// VaultCreationFailure is used when an error prevents a new data vault from being created.
	VaultCreationFailure = "Failed to create a new data vault: %s."

	// QueryFailReadRequestBody is used when the incoming request body can't be read.
	// This should not happen during normal operation.
	QueryFailReadRequestBody = `Received request to query data vault %s,` +
		" but failed to read the request body: %s."
	// InvalidQuery is used when an invalid query is received.
	InvalidQuery = `Received invalid query for data vault %s: %s.`
	// QueryFailure is used when an error occurs while querying a vault.
	QueryFailure = `Failure while querying vault %s: %s.`
	// QuerySuccess is used when a vault is successfully queried.
	QuerySuccess = `Successfully queried data vault %s.`
	// QueryNoMatchingDocs is used when a query returns no matching documents.
	QueryNoMatchingDocs = QuerySuccess + " No matching documents were found."
	// FailToMarshalDocIDs is used when the document IDs returned from a query can't be marshalled.
	// This should not happen during normal operation.
	FailToMarshalDocIDs = QuerySuccess + " Failed to marshal the matching document IDs into bytes: %s."

	// CreateDocumentFailReadRequestBody is used when the incoming request body can't be read.
	// This should not happen during normal operation.
	CreateDocumentFailReadRequestBody = `Received request to create a new document in data vault %s, ` +
		`but failed to read request body: %s`
	// InvalidDocument is used when an invalid document is received.
	InvalidDocument = `Received a request to create a document in vault %s, ` +
		"but the document is invalid: %s."
	// CreateDocumentFailure is used when an error occurs while creating a new document.
	CreateDocumentFailure = `Failure while creating document in vault %s: %s.`

	// ReadDocumentFailure is used when an error occurs while reading a document.
	ReadDocumentFailure = `Failed to read document %s in vault %s: %s`
	// ReadDocumentSuccess is used when a request document is successfully read.
	ReadDocumentSuccess = "Successfully retrieved document %s in vault %s."

	// InvalidLogSpec is used when a request is made to change the current log specification
	// but it is in an invalid format.
	InvalidLogSpec = `Invalid log spec. It needs to be in the following format: ` +
		`ModuleName1=Level1:ModuleName2=Level2:ModuleNameN=LevelN:AllOtherModuleDefaultLevel
Valid log levels: critical,error,warn,info,debug`
	// SetLogSpecSuccess is used when the current log specification is successfully changed.
	SetLogSpecSuccess = "Successfully set log level(s)."
	// GetLogSpecSuccess is used when the current log specification is successfully retrieved.
	GetLogSpecSuccess = "Successfully got log level(s)."
	// GetLogSpecPrepareErrMsg is used when an error occurs while preparing the
	// list of current log levels for the sender. This should not happen during normal operation.
	GetLogSpecPrepareErrMsg = "Failure while preparing log level response: %s"

	// UnescapeFailure is used when an error occurs while unescaping a path variable
	UnescapeFailure = "Unable to unescape %s path variable: %s."
)

type edvError string

// Error returns the associated EDV error message.
// This satisfies the built-in error interface.
func (e edvError) Error() string { return string(e) }
