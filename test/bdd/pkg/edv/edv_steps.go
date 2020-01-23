/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"fmt"

	"github.com/trustbloc/edv/pkg/client/edv"
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
	"github.com/trustbloc/edv/test/bdd/pkg/context"

	"github.com/DATA-DOG/godog"
)

// Steps is steps for EDV BDD tests
type Steps struct {
	bddContext *context.BDDContext
}

// NewSteps returns BDD test steps for EDV server
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers EDV server test steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Client sends request to create a new data vault with id "([^"]*)"`+
		` and receives the vault location "([^"]*)" in response$`, e.createDataVault)
	s.Step(`^EDV server has a data vault with id "([^"]*)"$`, e.edvServerRunningWithDataVault)
	s.Step(`^Client sends request to create a new document with id "([^"]*)" in the data vault with id "([^"]*)"`+
		` and receives the document location "([^"]*)" in response$`, e.createDocument)
	s.Step(`^The data vault with id "([^"]*)" has a document with id "([^"]*)"$`, e.vaultHasDocument)
	s.Step(`^Client sends request to retrieve the previously stored document with id "([^"]*)"`+
		` in the data vault with id "([^"]*)" and receives the document "([^"]*)" in response$`, e.receiveDocument)
}

func (e *Steps) createDataVault(vaultID, expectedVaultLocation string) error {
	client := edv.New(e.bddContext.EDVHostURL)

	config := operation.DataVaultConfiguration{ReferenceID: vaultID}

	vaultLocation, err := client.CreateDataVault(&config)
	if err != nil {
		return err
	}

	if vaultLocation != expectedVaultLocation {
		return fmt.Errorf("expected the new data vault location to be %s, got %s instead",
			expectedVaultLocation, vaultLocation)
	}

	return nil
}

func (e *Steps) edvServerRunningWithDataVault(vaultID string) error {
	err := e.createDataVault(vaultID, "localhost:8080/encrypted-data-vaults/"+vaultID)
	if err != nil {
		return err
	}

	return nil
}

func (e *Steps) createDocument(docID, vaultID, expectedDocLocation string) error {
	client := edv.New(e.bddContext.EDVHostURL)

	meta := make(map[string]interface{})
	meta["created"] = "2020-01-10"

	content := make(map[string]interface{})
	content["message"] = "Hello EDV!"

	document := operation.StructuredDocument{
		ID:      docID,
		Meta:    meta,
		Content: content,
	}

	docLocation, err := client.CreateDocument(vaultID, &document)
	if err != nil {
		return err
	}

	if docLocation != expectedDocLocation {
		return fmt.Errorf("expected the new data vault location to be %s, got %s instead", expectedDocLocation, docLocation)
	}

	return nil
}

func (e *Steps) vaultHasDocument(vaultID, docID string) error {
	err := e.createDocument(docID, vaultID, "localhost:8080/encrypted-data-vaults/"+vaultID+"/docs/"+docID)
	if err != nil {
		return err
	}

	return nil
}

func (e *Steps) receiveDocument(docID, vaultID, expectedDocumentArgKey string) error {
	client := edv.New(e.bddContext.EDVHostURL)

	document, err := client.RetrieveDocument(vaultID, docID)
	if err != nil {
		return err
	}

	expectedDocument := e.bddContext.Args[expectedDocumentArgKey]

	if string(document) != expectedDocument {
		return fmt.Errorf("expected the document to be %s, got %s instead", expectedDocument, string(document))
	}

	return nil
}
