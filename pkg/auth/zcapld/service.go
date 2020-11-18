/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/trustbloc/edge-core/pkg/zcapld"
)

const (
	storeName            = "zcap-capability"
	invocationTargetType = "urn:edv:vault"
)

// Service to provide zcapld functionality
type Service struct {
	keyManager kms.KeyManager
	crypto     cryptoapi.Crypto
	store      ariesstorage.Store
}

// New return zcap service
func New(keyManager kms.KeyManager, crypto cryptoapi.Crypto, storeProv ariesstorage.Provider) (*Service, error) {
	store, err := storeProv.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("failed to open store %s: %w", storeName, err)
	}

	return &Service{keyManager: keyManager, crypto: crypto, store: store}, nil
}

// Create zcap payload
func (s *Service) Create(resourceID, verificationMethod string) ([]byte, error) {
	rootCapability, err := s.createRootCapability(resourceID)
	if err != nil {
		return nil, err
	}

	signer, err := signature.NewCryptoSigner(s.crypto, s.keyManager, kms.ED25519)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto signer: %w", err)
	}

	id := uuid.New().URN()

	capability, err := zcapld.NewCapability(&zcapld.Signer{
		SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
		SuiteType:          ed25519signature2018.SignatureType,
		VerificationMethod: keyID(signer),
	}, zcapld.WithID(id), zcapld.WithParent(rootCapability.ID), zcapld.WithInvoker(verificationMethod),
		zcapld.WithInvocationTarget(resourceID, invocationTargetType))
	if err != nil {
		return nil, fmt.Errorf("failed to create new capability: %w", err)
	}

	capabilityBytes, err := json.Marshal(capability)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal capability: %w", err)
	}

	return capabilityBytes, nil
}

func (s *Service) createRootCapability(resourceID string) (*zcapld.Capability, error) {
	// create root capability and store in db
	signer, err := signature.NewCryptoSigner(s.crypto, s.keyManager, kms.ED25519)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto signer: %w", err)
	}

	rootID := uuid.New().URN()

	rootCapability, err := zcapld.NewCapability(&zcapld.Signer{
		SignatureSuite:     ed25519signature2018.New(suite.WithSigner(signer)),
		SuiteType:          ed25519signature2018.SignatureType,
		VerificationMethod: keyID(signer),
	}, zcapld.WithID(rootID), zcapld.WithParent(rootID), zcapld.WithInvocationTarget(resourceID, invocationTargetType))
	if err != nil {
		return nil, fmt.Errorf("failed to create new root capability: %w", err)
	}

	rootCapabilityBytes, err := json.Marshal(rootCapability)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal root capability: %w", err)
	}

	if err := s.store.Put(rootCapability.ID, rootCapabilityBytes); err != nil {
		return nil, fmt.Errorf("failed to store root capability: %w", err)
	}

	return rootCapability, nil
}

func keyID(sigSigner signature.Signer) string {
	// source: https://github.com/multiformats/multicodec/blob/master/table.csv.
	const ed25519pub = 0xed // Ed25519 public key in multicodec table

	thumb := fingerprint.KeyFingerprint(ed25519pub, sigSigner.PublicKeyBytes())

	return fmt.Sprintf("did:key:%s", thumb)
}
