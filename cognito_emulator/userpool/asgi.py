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

import base64
import json
import typing

import environs

from .application import create_application

env = environs.Env()
env.read_env()


def load_key(key: str) -> typing.Union[bytes, typing.Dict[str, str]]:
    bkey = base64.b64decode(key)
    try:
        payload = json.loads(bkey.decode("utf-8"))
        if not isinstance(payload, dict):
            raise TypeError()
        return payload
    except TypeError:
        pass
    return bkey


def extract_jwt_params_from_env(prefix: str) -> typing.Dict[str, str]:
    retval: typing.Dict[str, str] = {}
    for k, kk in (
        ("JKU", "jku"),
        ("JWK", "jwk"),
        ("X5U", "x5u"),
        ("X5C", "x5c"),
        ("X5T", "x5t"),
        ("X5T_S256", "x5t#S256"),
        ("CTY", "cty"),
        ("CRIT", "crit"),
        ("ENC", "enc"),
        ("ZIP", "zip"),
        ("TYP", "typ"),
    ):
        try:
            v = env.str(f"{prefix}{k}")
            retval[kk] = v
        except environs.EnvValidationError:
            pass
    return retval


jwt_key = env.str("JWT_KEY", None)

app = create_application(
    database_url=env.str("DATABASE_URL"),
    jwt_key=load_key(jwt_key) if jwt_key is not None else None,
    jwt_signature_algorithm=env.str("JWT_SIGNATURE_ALG"),
    jwt_signature_params=extract_jwt_params_from_env(prefix="JWT_SIGNATURE_"),
    jwt_encryption_algorithm=env.str("JWT_ENCRYPTION_ALG"),
    jwt_encryption_params=extract_jwt_params_from_env(prefix="JWT_ENCRYPTION_"),
    secret_key=env.str("SECRET_KEY"),
    region=env.str("EMULATED_REGION", "mars-east-1"),
    debug=env.bool("DEBUG", False),
)
