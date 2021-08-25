#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running EDV integration tests..."

PWD=`pwd`
cd test/bdd

# TODO (#220): Reduce BDD test running time by only starting storage containers as needed.

export EDV_DATABASE_TYPE=mongodb
export EDV_DATABASE_URL=mongodb://mongodb.example.com:27017
go test -count=1 -v -cover . -p 1 -timeout=20m -race

export EDV_DATABASE_TYPE=couchdb
export EDV_DATABASE_URL=admin:password@couchdb.example.com:5984
go test -count=1 -v -cover . -p 1 -timeout=20m -race

cd $PWD
