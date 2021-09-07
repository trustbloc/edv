#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@edv_interop_transmute
Feature: Demonstrating TrustBloc's EDV REST API interoperability with Transmute's implementation.

# TODO fix Transmute's EDV calls then uncomment the test below. See https://github.com/w3c-ccg/did-method-web/issues/25
# TODO Issue: https://github.com/trustbloc/edv/issues/224
#  @data_vault_creation
#  Scenario: Use EDV client to check for interoperability.
#    Then  Create a new data vault
#    Then  Attempt to create the same data vault again, resulting in a 409 error
#    Then  Create a new document
#    Then  Retrieve that newly created document
#    Then  Update the document
#    Then  Retrieve that updated document
