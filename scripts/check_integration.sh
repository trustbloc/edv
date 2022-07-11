#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

PWD=`pwd`
cd test/bdd

# TODO (#220): Reduce BDD test running time by only starting storage containers as needed.

echo "Running EDV integration tests using MongoDB + GNAP authorization..."

export EDV_DATABASE_TYPE=mongodb
export EDV_DATABASE_URL=mongodb://mongodb.example.com:27017
export EDV_AUTH_TYPE=GNAP
go test -count=1 -v -cover . -p 1 -timeout=20m -race

echo "Running EDV integration tests using MongoDB + ZCAP authorization..."

export EDV_DATABASE_TYPE=mongodb
export EDV_DATABASE_URL=mongodb://mongodb.example.com:27017
export EDV_AUTH_TYPE=ZCAP
go test -count=1 -v -cover . -p 1 -timeout=20m -race

echo "Running EDV integration tests using MongoDB + no authorization..."

export EDV_DATABASE_TYPE=mongodb
export EDV_DATABASE_URL=mongodb://mongodb.example.com:27017
export EDV_AUTH_TYPE=none
go test -count=1 -v -cover . -p 1 -timeout=20m -race

echo "Running EDV integration tests using CouchDB + GNAP authorization..."

export EDV_DATABASE_TYPE=couchdb
export EDV_DATABASE_URL=admin:password@couchdb.example.com:5984
export EDV_AUTH_TYPE=GNAP
go test -count=1 -v -cover . -p 1 -timeout=20m -race

cd $PWD
