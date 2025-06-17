#!/bin/sh
# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.

set -eux

KEYS="$(dirname "$0")/keys"
mkdir -p "${KEYS}"

export PASSWORD="hunter2"

convert() {
  FILE=$1
  NAME=$2
  openssl asn1parse -noout -in "${KEYS}/${FILE}.pem" -out "${KEYS}/${FILE}.der"
  openssl pkcs8 -topk8 -nocrypt -in "${KEYS}/${FILE}.pem" -out "${KEYS}/${NAME}.pkcs8.pem"
  openssl asn1parse -noout -in "${KEYS}/${NAME}.pkcs8.pem" -out "${KEYS}/${NAME}.pkcs8.der"
  openssl pkcs8 -topk8 -passout env:PASSWORD -in "${KEYS}/${FILE}.pem" -out "${KEYS}/${NAME}.pkcs8.encrypted.pem"
  openssl asn1parse -noout -in "${KEYS}/${NAME}.pkcs8.encrypted.pem" -out "${KEYS}/${NAME}.pkcs8.encrypted.der"
}

openssl genrsa -out "${KEYS}/rsa.pkcs1.pem" 2048
convert "rsa.pkcs1" "rsa"

openssl ecparam -genkey -name prime256v1 -noout -out "${KEYS}/ec-p256.sec1.pem"
convert "ec-p256.sec1" "ec-p256"

openssl ecparam -genkey -name secp384r1 -noout -out "${KEYS}/ec-p384.sec1.pem"
convert "ec-p384.sec1" "ec-p384"

openssl ecparam -genkey -name secp256k1 -noout -out "${KEYS}/ec-k256.sec1.pem"
convert "ec-k256.sec1" "ec-k256"
