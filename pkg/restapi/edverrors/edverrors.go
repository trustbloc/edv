/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edverrors

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

	// BlankReferenceIDErrMsg is the message returned by the EDV server when an attempt is made to create a vault
	// with a blank reference ID.
	BlankReferenceIDErrMsg = "referenceId can't be blank"
)

type edvError string

// Error returns the associated EDV error message.
// This satisfies the built-in error interface.
func (e edvError) Error() string { return string(e) }
