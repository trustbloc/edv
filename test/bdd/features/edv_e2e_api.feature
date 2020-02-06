#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@edv_rest
Feature: Using EDV REST API

  @create_new_vault
  Scenario: Client creates a new data vault
    Then  Client sends request to create a new data vault with id "testvault" and receives the vault location "localhost:8080/encrypted-data-vaults/testvault" in response

  @create_new_document
  Scenario: Client creates a new document
    Given EDV server has a data vault with id "testvault2"
    Then  Client sends request to create a new document with id "VJYHHJx4C8J9Fsgz7rZqSp" in the data vault with id "testvault2" and receives the document location "localhost:8080/encrypted-data-vaults/testvault2/docs/VJYHHJx4C8J9Fsgz7rZqSp" in response

  @read_document
  Scenario: Client retrieves a previously stored document
    Given EDV server has a data vault with id "testvault3"
    Given The data vault with id "testvault3" has a document with id "VJYHHJx4C8J9Fsgz7rZqSp"
    Then  Client sends request to retrieve the previously stored document with id "VJYHHJx4C8J9Fsgz7rZqSp" in the data vault with id "testvault3" and receives the document "${EXPECTED_DOCUMENT}" in response