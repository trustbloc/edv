/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package interop

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/edv/pkg/restapi/models"
	"github.com/trustbloc/edv/test/bdd/pkg/common"
	"github.com/trustbloc/edv/test/bdd/pkg/context"
)

const statusCode409Msg = "status code 409"

// Steps is steps for EDV BDD tests
type Steps struct {
	bddInteropContext *context.BDDInteropContext
}

// NewSteps returns BDD test steps for EDV server
func NewSteps(ctx *context.BDDInteropContext) *Steps {
	return &Steps{bddInteropContext: ctx}
}

// RegisterSteps registers EDV server test steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Create a new data vault$`, e.createDataVault)
	s.Step(`^Attempt to create the same data vault again, resulting in a 409 error$`, e.createDataVaultAgain)
	s.Step(`^Create a new document$`, e.createDocument)
	s.Step(`^Retrieve that newly created document$`, e.retrieveDocument)
	s.Step(`^Update the document$`, e.updateDocument)
	s.Step(`^Retrieve that updated document$`, e.retrieveDocument)
}

func (e *Steps) createDataVault() error {
	vaultRefID := uuid.New().String()
	e.bddInteropContext.DataVaultConfig = &models.DataVaultConfiguration{
		Sequence:    0,
		Controller:  e.bddInteropContext.VerificationMethod,
		ReferenceID: vaultRefID,
		KEK:         models.IDTypePair{ID: "https://example.com/kms/12345", Type: "AesKeyWrappingKey2019"},
		HMAC:        models.IDTypePair{ID: "https://example.com/kms/67891", Type: "Sha256HmacKey2019"},
	}

	err := e.trustBlocCreateDataVault()
	if err != nil {
		return err
	}

	err = e.transmuteCreateDataVault()
	if err != nil {
		return err
	}

	return nil
}

func (e *Steps) trustBlocCreateDataVault() error {
	trustBlocEDVLocation, resp, err :=
		e.bddInteropContext.TrustBlocEDVClient.CreateDataVault(e.bddInteropContext.DataVaultConfig)
	if err != nil {
		return err
	}

	trustBlocEDVLocationWithTrailingSlash := "edv/encrypted-data-vaults/"
	if !strings.HasPrefix(trustBlocEDVLocation, trustBlocEDVLocationWithTrailingSlash) {
		return errors.New("the trustBloc data vault location is " + trustBlocEDVLocation +
			". It was expected to start with " + trustBlocEDVLocationWithTrailingSlash + " but it didn't")
	}

	e.bddInteropContext.TrustBlocDataVaultLocation = trustBlocEDVLocation

	trustBlocDataVaultLocationURLSplitUp := strings.Split(trustBlocEDVLocation, "/")
	e.bddInteropContext.TrustBlocEDVDataVaultID =
		trustBlocDataVaultLocationURLSplitUp[len(trustBlocDataVaultLocationURLSplitUp)-1]

	capability, err := zcapld.ParseCapability(resp)
	if err != nil {
		return err
	}

	if capability.Context != zcapld.SecurityContextV2 {
		return fmt.Errorf("wrong ctx return for zcapld")
	}

	e.bddInteropContext.Capability = capability

	return nil
}

func (e *Steps) transmuteCreateDataVault() error {
	transmuteDataVaultLocation, _, err :=
		e.bddInteropContext.TransmuteEDVClient.CreateDataVault(e.bddInteropContext.DataVaultConfig)
	if err != nil {
		return err
	}

	transmuteEDVURLWithTrailingSlash := e.bddInteropContext.TransmuteEDVHostURL + "/"
	if !strings.HasPrefix(transmuteDataVaultLocation, transmuteEDVURLWithTrailingSlash) {
		return errors.New("the transmute data vault location is " + transmuteDataVaultLocation +
			". It was expected to start with " + transmuteEDVURLWithTrailingSlash + " but it didn't")
	}

	e.bddInteropContext.TransmuteDataVaultLocation = transmuteDataVaultLocation

	transmuteDataVaultLocationURLSplitUp := strings.Split(transmuteDataVaultLocation, "/")
	e.bddInteropContext.TransmuteDataVaultID =
		transmuteDataVaultLocationURLSplitUp[len(transmuteDataVaultLocationURLSplitUp)-1]

	return nil
}

func (e *Steps) createDataVaultAgain() error {
	_, _, errTrustBlocCreateVault :=
		e.bddInteropContext.TrustBlocEDVClient.CreateDataVault(e.bddInteropContext.DataVaultConfig)

	if !strings.Contains(errTrustBlocCreateVault.Error(), statusCode409Msg) {
		return errors.New("expected Transmute duplicate vault creation attempt to result in a 409 error, " +
			"but got " + errTrustBlocCreateVault.Error() + " instead")
	}

	_, _, errTransmuteCreateVault :=
		e.bddInteropContext.TransmuteEDVClient.CreateDataVault(e.bddInteropContext.DataVaultConfig)

	if !strings.Contains(errTransmuteCreateVault.Error(), statusCode409Msg) {
		return errors.New("expected Transmute duplicate vault creation attempt to result in a 409 error, " +
			"but got " + errTransmuteCreateVault.Error() + " instead")
	}

	return nil
}

func (e *Steps) createDocument() error {
	trustBlocDocLocation, err :=
		e.bddInteropContext.TrustBlocEDVClient.CreateDocument(e.bddInteropContext.TrustBlocEDVDataVaultID,
			e.bddInteropContext.SampleDocToStore)
	if err != nil {
		return err
	}

	expectedTrustBlocDocLocation := "edv/encrypted-data-vaults/" +
		e.bddInteropContext.TrustBlocEDVDataVaultID + "/documents/" + e.bddInteropContext.SampleDocToStore.ID
	if trustBlocDocLocation != expectedTrustBlocDocLocation {
		return common.UnexpectedValueError(expectedTrustBlocDocLocation, trustBlocDocLocation)
	}

	transmuteDocLocation, err := e.bddInteropContext.TransmuteEDVClient.CreateDocument(
		e.bddInteropContext.TransmuteDataVaultID, e.bddInteropContext.SampleDocToStore)
	if err != nil {
		return err
	}

	expectedTransmuteDocLocation := e.bddInteropContext.TransmuteDataVaultLocation + "/documents/" +
		e.bddInteropContext.SampleDocToStore.ID
	if transmuteDocLocation != expectedTransmuteDocLocation {
		return common.UnexpectedValueError(expectedTransmuteDocLocation, expectedTransmuteDocLocation)
	}

	return nil
}

func (e *Steps) retrieveDocument() error {
	retrievedDocFromTrustBlocEDV, err := e.bddInteropContext.TrustBlocEDVClient.ReadDocument(
		e.bddInteropContext.TrustBlocEDVDataVaultID, e.bddInteropContext.SampleDocToStore.ID)
	if err != nil {
		return err
	}

	retrievedDocFromTransmuteEDV, err := e.bddInteropContext.TransmuteEDVClient.ReadDocument(
		e.bddInteropContext.TransmuteDataVaultID, e.bddInteropContext.SampleDocToStore.ID)
	if err != nil {
		return err
	}

	marshalledRetrievedDocFromTrustBlocEDV, err := json.Marshal(retrievedDocFromTrustBlocEDV)
	if err != nil {
		return err
	}

	marshalledRetrievedDocFromTransmuteEDV, err := json.Marshal(retrievedDocFromTransmuteEDV)
	if err != nil {
		return err
	}

	if string(marshalledRetrievedDocFromTrustBlocEDV) != string(marshalledRetrievedDocFromTransmuteEDV) {
		return errors.New("expected the documents returned from both EDV implementations to be the same, but " +
			"they're not. The document from the TrustBloc EDV is " + string(marshalledRetrievedDocFromTrustBlocEDV) +
			" and the document from the Transmute EDV is " + string(marshalledRetrievedDocFromTransmuteEDV))
	}

	return nil
}

func (e *Steps) updateDocument() error {
	err := e.bddInteropContext.TrustBlocEDVClient.UpdateDocument(e.bddInteropContext.TrustBlocEDVDataVaultID,
		e.bddInteropContext.SampleDocForUpdate.ID, e.bddInteropContext.SampleDocForUpdate)
	if err != nil {
		return err
	}

	err = e.bddInteropContext.TransmuteEDVClient.UpdateDocument(e.bddInteropContext.TransmuteDataVaultID,
		e.bddInteropContext.SampleDocForUpdate.ID, e.bddInteropContext.SampleDocForUpdate)
	if err != nil {
		return err
	}

	return nil
}
