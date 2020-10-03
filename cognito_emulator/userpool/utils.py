# Copyright (c) 2020 Open Collector, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import typing

from authlib.jose.jwk import JsonWebKey  # type: ignore
from authlib.jose.rfc7518._cryptography_backends._keys import (  # type: ignore
    ECKey,
    RSAKey,
)

from ..utils import generate_key


def generate_jwk(typ: str) -> typing.Union[typing.Dict[str, str], bytes]:
    typ = typ.lower()
    if typ.startswith("rs"):
        return generate_jwk_rsa().as_dict()
    elif typ.startswith("es"):
        return generate_jwk_ec(typ).as_dict()
    elif typ.startswith("hs"):
        return (generate_key(int(typ[2:]) // 8)).encode("ascii")
    elif typ in ("a128kw", "a256kw", "a512kw"):
        return (generate_key(int(typ[1:4]) // 8)).encode("ascii")
    else:
        raise ValueError(f"unsupported jws/jwe type: {typ}")


def generate_jwk_rsa() -> RSAKey:
    return RSAKey.generate_key(key_size=2048, is_private=True)


def generate_jwk_ec(typ: str) -> ECKey:
    curve = {
        "es256": "P-256",
        "es384": "P-384",
        "es512": "P-512",
    }
    return ECKey.generate_key(curve.get(typ, "P-384"), is_private=True)


def build_jwt_public_key_from_private_key(
    private_jwk: typing.Dict[str, str]
) -> typing.Dict[str, str]:
    private_key: typing.Union[RSAKey, ECKey] = JsonWebKey.import_key(private_jwk, None)
    public_jwk = private_key.dumps_public_key(private_key.get_public_key())  # type: ignore
    public_jwk["kty"] = private_key.kty
    if "kid" in private_jwk:
        public_jwk["kid"] = private_jwk["kid"]
    return public_jwk
