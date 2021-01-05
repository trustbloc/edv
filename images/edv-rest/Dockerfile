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


FROM alpine:${ALPINE_VER}

LABEL org.opencontainers.image.source https://github.com/trustbloc/edv

# copy compiled edv-rest binary from build container
COPY --from=edv /go/src/github.com/trustbloc/edv/build/bin/edv-rest /usr/local/bin

# set up nsswitch.conf for Go's "netgo" implementation
# - https://github.com/golang/go/blob/go1.9.1/src/net/conf.go#L194-L275
RUN [ ! -e /etc/nsswitch.conf ] && echo 'hosts: files dns' > /etc/nsswitch.conf

# setting entrypoint to the binary itself
ENTRYPOINT ["edv-rest"]
