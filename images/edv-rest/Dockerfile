#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang
RUN apk add --no-cache \
	gcc \
	musl-dev \
	git \
	libtool \
	bash \
	make;
ADD . src/github.com/trustbloc/edv
WORKDIR src/github.com/trustbloc/edv
ENV EXECUTABLES go git

FROM golang as edv
RUN make edv-rest


FROM alpine:${ALPINE_VER} as base
COPY --from=edv /go/src/github.com/trustbloc/edv/build/bin/edv-rest /usr/local/bin
ENTRYPOINT ["edv-rest"]
