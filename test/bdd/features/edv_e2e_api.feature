#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@edv_rest
Feature: Using EDV REST API

  @e2e
  Scenario: Full end-to-end flow. Create a data vault, store an encrypted document, and then retrieve the encrypted document. Query using an encrypted index.
    Then  Client sends request to create a new data vault with id "testvault" and receives the vault location "localhost:8080/encrypted-data-vaults/testvault" in response
    Then  Client constructs a Structured Document with id "VJYHHJx4C8J9Fsgz7rZqSp"
    Then  Client encrypts the Structured Document and uses it to construct an Encrypted Document
    Then  Client stores the Encrypted Document in the data vault with id "testvault" and receives the document location "localhost:8080/encrypted-data-vaults/testvault/documents/VJYHHJx4C8J9Fsgz7rZqSp" in response
    Then  Client sends request to retrieve the previously stored Encrypted Document with id "VJYHHJx4C8J9Fsgz7rZqSp" in the data vault with id "testvault" and receives the previously stored Encrypted Document in response
    Then  Client decrypts the Encrypted Document it received in order to reconstruct the original Structured Document
    Then  Client queries the vault with id "testvault" to find the previously created document with an encrypted index named "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ" with associated value "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
