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
	FailWriteResponse = " Failed to write response back to sender: %s."

	// DebugLogEvent is used for logging debugging events.
	DebugLogEvent = `
Event: %s`
	// DebugLogEventWithReceivedData is used for logging debugging events with received data.
	DebugLogEventWithReceivedData = DebugLogEvent + `
Received data: %s`

	// CreateVaultFailReadRequestBody is used when the incoming request body can't be read..
	// This should not happen during normal operation.
	CreateVaultFailReadRequestBody = "Received request to create a new data vault, " +
		"but failed to read the request body: %s."
	// InvalidVaultConfig is used when a received data vault configuration is invalid.
	InvalidVaultConfig = "Received invalid data vault configuration: %s."
	// StoreVaultConfigFailure is used when an error prevents a data vault configuration from being stored.
	StoreVaultConfigFailure = "failed to store data vault configuration: %s"
	// ConfigStoreNotFound is used when the configuration store can not be found
	ConfigStoreNotFound = "configuration store not found"
	// CheckDuplicateRefIDFailure is used when an error occurs while querying referenceIds
	CheckDuplicateRefIDFailure = "an error occurred while querying reference IDs: %s"
	// FailToMarshalConfig is used when a data vault configuration can't be marshalled
	// This should not happen during normal operation.
	FailToMarshalConfig = "failed to marshal data vault configuration into bytes %s"
	// BlankController is the message returned by the EDV server when a attempt is made to create a vault
	// with a blank controller.
	BlankController = "controller can't be blank"
	// BlankKEKID is the message returned by the EDV server when a attempt is made to create a vault
	// with a blank key agreement key ID.
	BlankKEKID = "key agreement key ID can't be blank"
	// BlankKEKType is the message returned by the EDV server when a attempt is made to create a vault
	// with a blank key agreement key type.
	BlankKEKType = "key agreement key type can't be blank"
	// BlankHMACID is the message returned by the EDV server when a attempt is made to create a vault
	// with a blank HMAC ID.
	BlankHMACID = "HMAC ID can't be blank"
	// BlankHMACType is the message returned by the EDV server when a attempt is made to create a vault
	// with a blank HMAC type.
	BlankHMACType = "HMAC type can't be blank"
	// InvalidURI is used when the value is not a valid URI.
	InvalidURI = "'%s' is not a valid URI"
	// InvalidControllerString is the message returned by the EDV server when a attempt is made to create a vault
	// with an invalid controller value.
	InvalidControllerString = "invalid controller value: %w"
	// InvalidInvokerStringArray is the message returned by the EDV server when a attempt is made to create a vault
	// with invalid invoker values.
	InvalidInvokerStringArray = "invalid invoker value: %w"
	// InvalidDelegatorStringArray is the message returned by the EDV server when a attempt is made to create a vault
	// with invalid delegator values.
	InvalidDelegatorStringArray = "invalid delegator value: %w"
	// InvalidKEKIDString is the message returned by the EDV server when a attempt is made to create a vault
	// with an invalid key agreement key ID value.
	InvalidKEKIDString = "invalid key agreement key ID: %w"
	// VaultCreationFailure is used when an error prevents a new data vault from being created.
	VaultCreationFailure = "Failed to create a new data vault: %s."
	// MarshalVaultConfigForLogFailure is used when the log level is set to debug and a data vault configuration
	// fails to marshal back into bytes for logging purposes.
	MarshalVaultConfigForLogFailure = "Failed to marshal vault config back into bytes for logging purposes: %s."

	// QueryReceiveRequest is used for logging new queries.
	QueryReceiveRequest = "Received request to query data vault %s."
	// BatchReceiveRequest is used for logging new batch operation requests.
	BatchReceiveRequest = "Received request to do a batch operation in data vault %s."
	// QueryFailReadRequestBody is used when the incoming request body can't be read.
	// This should not happen during normal operation.
	QueryFailReadRequestBody = QueryReceiveRequest + " Failed to read the request body: %s."
	// BatchFailReadRequestBody is used when the incoming request body can't be read.
	// This should not happen during normal operation.
	BatchFailReadRequestBody = BatchReceiveRequest + " Failed to read the request body: %s."
	// InvalidQuery is used when an invalid query is received.
	InvalidQuery = `Received invalid query for data vault %s: %s.`
	// InvalidBatch is used when an invalid batch operation is received.
	InvalidBatch = `Received invalid batch operation for data vault %s: %s.`
	// QueryFailure is used when an error occurs while querying a vault.
	QueryFailure = `Failure while querying vault %s: %s.`
	// QuerySuccess is used when a vault is successfully queried.
	QuerySuccess = `Successfully queried data vault %s.`
	// FailToMarshalDocIDs is used when the document IDs returned from a query can't be marshalled.
	// This should not happen during normal operation.
	FailToMarshalDocIDs = QuerySuccess + " Failed to marshal the matching document IDs into bytes: %s."
	// FailToMarshalDocuments is used when the documents returned from a query can't be marshalled.
	// This should not happen during normal operation.
	FailToMarshalDocuments = QuerySuccess + " Failed to marshal the matching documents into bytes: %s."
	// MarshalQueryForLogFailure is used when the log level is set to debug and a query
	// fails to marshal back into bytes for logging purposes.
	MarshalQueryForLogFailure = "Failed to marshal query back into bytes for logging purposes: %s."
	// MarshalBatchForLogFailure is used when the log level is set to debug and a batch request
	// fails to marshal back into bytes for logging purposes.
	MarshalBatchForLogFailure = "Failed to marshal batch request back into bytes for logging purposes: %s."

	// CreateDocumentReceiveRequest is used for logging create document requests.
	CreateDocumentReceiveRequest = "Received request to create a new document in data vault %s."
	// CreateDocumentFailReadRequestBody is used when the incoming request body can't be read.
	// This should not happen during normal operation.
	CreateDocumentFailReadRequestBody = CreateDocumentReceiveRequest +
		` Failed to read request body: %s.`
	// InvalidDocumentForDocCreation is used when an invalid document is received while creating a document.
	InvalidDocumentForDocCreation = `Received a request to create a document in vault %s, ` +
		"but the document is invalid: %s."
	// InvalidRawJWE is used when the JWE in a document is invalid.
	InvalidRawJWE = "invalid raw JWE: %s"
	// BlankJWE is used when the JWE field in an encrypted document is empty
	BlankJWE = "JWE can't be empty"
	// BlankJWEAlg is used when the JWE alg field in an encrypted document is empty
	BlankJWEAlg = "JWE alg can't be empty"
	// Base64DecodeJWEProtectedHeadersFailure is used when an error occurs while base64-decoding the JWE protected
	// headers.
	Base64DecodeJWEProtectedHeadersFailure = "failed to decode JWE protected headers"
	// BadJWEProtectedHeaders is used when the decoded protected header is not in 'key':'value' format.
	BadJWEProtectedHeaders = "bad JWE protected header"
	// CreateDocumentFailure is used when an error occurs while creating a new document.
	CreateDocumentFailure = `Failure while creating document in vault %s: %s.`
	// CreateDocumentSuccess is used when a document is successfully created.
	CreateDocumentSuccess = "Successfully created a new document in vault %s at %s."
	// MarshalDocumentForLogFailure is used when the log level is set to debug and a document
	// fails to marshal back into bytes for logging purposes.
	MarshalDocumentForLogFailure = "Failed to marshal document back into bytes for logging purposes: %s."

	// ReadAllDocumentsReceiveRequest is used for logging read all documents requests.
	ReadAllDocumentsReceiveRequest = "Received request to read all documents from data vault %s."
	// ReadAllDocumentsFailure is used when an error occurs while reading all documents.
	ReadAllDocumentsFailure = `Failed to read all documents in vault %s: %s.`
	// ReadAllDocumentsSuccess is used when all documents are successfully read.
	ReadAllDocumentsSuccess = "Successfully retrieved all documents in vault %s."
	// ReadAllDocumentsSuccessWithRetrievedDocs is used when all request documents are successfully read.
	// Includes the content of the retrieved documents.
	ReadAllDocumentsSuccessWithRetrievedDocs = "Successfully retrieved all documents in vault %s. " +
		"Retrieved docs: %s"
	// FailToMarshalAllDocuments is used when the returned array of documents fails to marshal.
	// This should not happen during normal operation.
	FailToMarshalAllDocuments = ReadAllDocumentsSuccess + " Failed to marshal the documents: %s"

	// ReadDocumentReceiveRequest is used for logging read document requests.
	ReadDocumentReceiveRequest = "Received request to read document %s from data vault %s."
	// ReadDocumentFailure is used when an error occurs while reading a document.
	ReadDocumentFailure = `Failed to read document %s in vault %s: %s.`
	// ReadDocumentSuccess is used when a request document is successfully read.
	ReadDocumentSuccess = "Successfully retrieved document %s in vault %s."
	// ReadDocumentSuccessWithRetrievedDoc is used when a request document is successfully read.
	// Includes the retrieved document contents.
	ReadDocumentSuccessWithRetrievedDoc = "Successfully retrieved document %s in vault %s. Retrieved doc: %s"

	// UpdateDocumentReceiveRequest is used for logging update document requests.
	UpdateDocumentReceiveRequest = "Received request to update document %s from data vault %s."
	// UpdateDocumentFailReadRequestBody is used when the incoming request body can't be read.
	// This should not happen during normal operation.
	UpdateDocumentFailReadRequestBody = UpdateDocumentReceiveRequest + ` Failed to read request body: %s.`
	// MismatchedDocIDs is used when docIDs obtained from the path variable and the request body are different.
	MismatchedDocIDs = "document IDs from the path variable and the request body have to be the same"
	// InvalidDocumentForDocUpdate is used when an invalid document is received while updating a document.
	InvalidDocumentForDocUpdate = `Received a request to update document %s in vault %s, ` +
		"but the document is invalid: %s."
	// UpdateMappingDocumentFailure is used when an error occurs while updating the mapping document
	// for the given document.
	UpdateMappingDocumentFailure = "failed to update mapping document for document %s: %s"
	// UpdateDocumentFailure is used when an error occurs while updating a document.
	UpdateDocumentFailure = `Failed to update document %s in vault %s: %s.`
	// UpdateDocumentSuccess is used when a request document is successfully updated.
	UpdateDocumentSuccess = "Successfully updated document %s in vault %s."

	// DeleteDocumentReceiveRequest is used for logging delete document requests.
	DeleteDocumentReceiveRequest = "Received request to delete document %s from data vault %s."
	// DeleteDocumentFailure is used when an error occurs while deleting a document.
	DeleteDocumentFailure = `Failed to delete document %s in vault %s: %s.`
	// DeleteMappingDocumentFailure is used when an error occurs while deleting a mapping document for the document.
	DeleteMappingDocumentFailure = "failed to delete mapping document: %s"

	// BatchResponseSuccess is used when all operations within a batch request execute successfully.
	BatchResponseSuccess = `Successfully performed batch operation. Vault ID: %s, Request: %s, Response: %s`
	// BatchResponseFailure is used when one or more operations within a batch request fail.
	BatchResponseFailure = `Failure during batch operation. Vault ID: %s, Request: %s, Response: %s`

	// PutLogSpecFailReadRequestBody is used when the incoming request body can't be read.
	// This should not happen during normal operation.
	PutLogSpecFailReadRequestBody = "Received request to change the log spec, " +
		"but failed to read the request body: %s."
	// InvalidLogSpec is used when a request is made to change the current log specification
	// but it is in an invalid format.
	InvalidLogSpec = `Invalid log spec. It needs to be in the following format: ` +
		`ModuleName1=Level1:ModuleName2=Level2:ModuleNameN=LevelN:AllOtherModuleDefaultLevel
Valid log levels: critical,error,warn,info,debug
Error: %s`
	// SetLogSpecSuccess is used when the current log specification is successfully changed.
	SetLogSpecSuccess = "Successfully set log level(s)."
	// MultipleDefaultValues is used when an incoming log spec defines multiple default values, which is invalid.
	MultipleDefaultValues = "multiple default values found"

	// GetLogSpecSuccess is used when the current log specification is successfully retrieved.
	GetLogSpecSuccess = "Successfully got log level(s)."
	// GetLogSpecPrepareErrMsg is used when an error occurs while preparing the
	// list of current log levels for the sender. This should not happen during normal operation.
	GetLogSpecPrepareErrMsg = "Failure while preparing log level response: %s."

	// UnescapeFailure is used when an error occurs while unescaping a path variable
	UnescapeFailure = "Unable to unescape %s path variable: %s."

	// FailWhileGetAllDocsFromStoreErrMsg is used when there's a failure while getting all documents from an
	// underlying store
	FailWhileGetAllDocsFromStoreErrMsg = "failure while getting all documents from store: %w"
)

type edvError string

// Error returns the associated EDV error message.
// This satisfies the built-in error interface.
func (e edvError) Error() string { return string(e) }
