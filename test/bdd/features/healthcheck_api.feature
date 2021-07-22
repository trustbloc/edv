#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@healthcheck
Feature: health check

  Scenario Outline:
    When an HTTP GET is sent to "<url>"
    Then the JSON path "<respKey>" of the response equals "<respKeyVal>"
    Examples:
      | url                                            | respKey       | respKeyVal                                      |
      | https://localhost:8076/healthcheck              | status        | success                                         |
