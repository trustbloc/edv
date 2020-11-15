#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@edv_rest
Feature: Using EDV REST API

  @e2e
  Scenario: Full end-to-end flow. Create a data vault, store an encrypted document, and then retrieve the encrypted document. Query using an encrypted index. Update an encrypted document, and then retrieve the encrypted document.
    Given the wallet is registered as an OIDC client
    When the wallet redirects the user to authenticate at hub-auth
    And the user picks their third party OIDC provider
    And the user authenticates with the third party OIDC provider
    Then the user is redirected back to the wallet
    And the user has authenticated to the wallet
    Then  Client sends request to create a new data vault and receives the vault location
    Then  Client constructs a Structured Document with id "VJYHHJx4C8J9Fsgz7rZqSp"
    Then  Client encrypts the Structured Document and uses it to construct an Encrypted Document
    Then  Client stores the Encrypted Document in the data vault
    Then  Client sends request to retrieve the previously stored Encrypted Document with id "VJYHHJx4C8J9Fsgz7rZqSp" in the data vault and receives the previously stored Encrypted Document in response
    Then  Client decrypts the Encrypted Document it received in order to reconstruct the original Structured Document
    Then  Client queries the vault to find the previously created document with an encrypted index named "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ" with associated value "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
    Then  Client changes the Structured Document with id "VJYHHJx4C8J9Fsgz7rZqSp" in order to update the Encrypted Document in the data vault
    Then  Client encrypts the new Structured Document and uses it to construct an Encrypted Document
    Then  Client updates Structured Document with id "VJYHHJx4C8J9Fsgz7rZqSp" in the data vault
    Then  Client sends request to retrieve the updated Encrypted Document with id "VJYHHJx4C8J9Fsgz7rZqSp" in the data vault and receives the updated Encrypted Document in response
    Then  Client decrypts the Encrypted Document it received in order to reconstruct the original Structured Document
