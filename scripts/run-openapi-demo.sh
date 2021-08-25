#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


#TODO (#104): Fix OpenAPI demo

set -e

DEMO_COMPOSE_OP="${DEMO_COMPOSE_OP:-up --force-recreate}"

FIXTURES_ABS_PATH="$PWD/$FIXTURES_PATH"

declare -a features=(
                "edv-rest"
                "openapi-demo"
               )

for feature in "${features[@]}"
do
   cd "$FIXTURES_ABS_PATH/$feature"
   docker-compose -f docker-compose.yml ${DEMO_COMPOSE_OP} -d
done