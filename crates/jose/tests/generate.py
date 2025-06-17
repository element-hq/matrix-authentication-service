# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.

# Generates test keys, JWKS and JWTs
# Required the `openssl` binary and the `authlib` python library

import json
import subprocess
from pathlib import Path
from typing import List

from authlib.jose import JsonWebKey, JsonWebSignature, KeySet

output_path = Path(__file__).parent

keys_path = output_path / "keys"
keys_path.mkdir(parents=True, exist_ok=True)

jwts_path = output_path / "jwts"
jwts_path.mkdir(parents=True, exist_ok=True)


def gen_key(
    name: str,
    priv_command: List[str],
    pub_command: List[str],
):
    """Generate a keypair

    Args:
        name: Name
        priv_command: Command to generate the private key. This must write the
            key to stdout.
        pub_command: Command to convert the private key to a public one. This
            must read the private key from stdin and write the public key to
            stdout.
    """
    priv_path = keys_path / f"{name}.priv.pem"
    pub_path = keys_path / f"{name}.pub.pem"

    with open(priv_path, "wb") as f:
        subprocess.run(priv_command, stdout=f, stderr=subprocess.DEVNULL)

    with open(priv_path, "rb") as priv, open(pub_path, "wb") as pub:
        subprocess.run(pub_command, stdin=priv, stdout=pub, stderr=subprocess.DEVNULL)


def import_key(name: str, kty: str) -> JsonWebKey:
    """Import a key from a file"""
    with open(keys_path / name, "r") as f:
        pem = f.read()
    return JsonWebKey.import_key(pem, {"kty": kty})


def sign_jwt(alg: str, filename: str, key: JsonWebKey):
    """Sign a JWT for the given key"""
    path = jwts_path / filename
    protected = {"alg": alg, "kid": key.thumbprint()}
    payload = '{"hello":"world"}'
    jws = JsonWebSignature(algorithms=[alg])
    jwt = jws.serialize_compact(protected, payload, key)
    with open(path, "wb") as f:
        f.write(jwt)


with open(keys_path / "oct.bin", "wb") as f:
    subprocess.run(
        ["openssl", "rand", "-hex", "64"], stdout=f, stderr=subprocess.DEVNULL
    )

gen_key("rsa", ["openssl", "genrsa", "2048"], ["openssl", "rsa", "-pubout"])
gen_key(
    "p256",
    ["openssl", "ecparam", "-genkey", "-name", "prime256v1"],
    ["openssl", "ec", "-pubout"],
)
gen_key(
    "p384",
    ["openssl", "ecparam", "-genkey", "-name", "secp384r1"],
    ["openssl", "ec", "-pubout"],
)
gen_key(
    "p521",
    ["openssl", "ecparam", "-genkey", "-name", "secp521r1"],
    ["openssl", "ec", "-pubout"],
)
gen_key(
    "k256",
    ["openssl", "ecparam", "-genkey", "-name", "secp256k1"],
    ["openssl", "ec", "-pubout"],
)
gen_key(
    "ed25519",
    ["openssl", "genpkey", "-algorithm", "ed25519"],
    ["openssl", "pkey", "-pubout"],
)
gen_key(
    "ed448",
    ["openssl", "genpkey", "-algorithm", "ed448"],
    ["openssl", "pkey", "-pubout"],
)

oct_key = import_key("oct.bin", "oct")
rsa_key = import_key("rsa.priv.pem", "RSA")
p256_key = import_key("p256.priv.pem", "EC")
p384_key = import_key("p384.priv.pem", "EC")
p521_key = import_key("p521.priv.pem", "EC")
k256_key = import_key("k256.priv.pem", "EC")
ed25519_key = import_key("ed25519.priv.pem", "OKP")
ed448_key = import_key("ed448.priv.pem", "OKP")

key_set = KeySet(
    [rsa_key, p256_key, p384_key, p521_key, k256_key, ed25519_key, ed448_key]
)

with open(keys_path / "jwks.pub.json", "w", encoding="utf8") as f:
    json.dump(key_set.as_dict(is_private=False), f, indent=2, sort_keys=True)

key_set.keys.insert(0, oct_key)

with open(keys_path / "jwks.priv.json", "w", encoding="utf8") as f:
    json.dump(key_set.as_dict(is_private=True), f, indent=2, sort_keys=True)

sign_jwt("HS256", "hs256.jwt", oct_key)
sign_jwt("HS384", "hs384.jwt", oct_key)
sign_jwt("HS512", "hs512.jwt", oct_key)
sign_jwt("RS256", "rs256.jwt", rsa_key)
sign_jwt("RS384", "rs384.jwt", rsa_key)
sign_jwt("RS512", "rs512.jwt", rsa_key)
sign_jwt("RS256", "rs256.jwt", rsa_key)
sign_jwt("RS384", "rs384.jwt", rsa_key)
sign_jwt("RS512", "rs512.jwt", rsa_key)
sign_jwt("PS256", "ps256.jwt", rsa_key)
sign_jwt("PS384", "ps384.jwt", rsa_key)
sign_jwt("PS512", "ps512.jwt", rsa_key)
sign_jwt("ES256", "es256.jwt", p256_key)
sign_jwt("ES384", "es384.jwt", p384_key)
sign_jwt("ES512", "es512.jwt", p521_key)
sign_jwt("ES256K", "es256k.jwt", k256_key)
sign_jwt("EdDSA", "eddsa-ed25519.jwt", ed25519_key)
sign_jwt("EdDSA", "eddsa-ed448.jwt", ed448_key)
