#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@edv_interop_transmute
Feature: Demonstrating TrustBloc's EDV REST API interoperability with Transmute's implementation. [Temporarily disabled]

# TODO (#224) rework interop tests - the Transmute implementation we used to test against is no longer online
#  @data_vault_creation
#  Scenario: Use EDV client to check for interoperability.
#    Then  Create a new data vault
#    Then  Attempt to create the same data vault again, resulting in a 409 error
#    Then  Create a new document
#    Then  Retrieve that newly created document
#    Then  Update the document
#    Then  Retrieve that updated document
