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

import json
import logging

import pytest
from starlette.endpoints import HTTPEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def setup_database(app):
    from cognito_emulator.db import metadata, session_factory

    metadata.create_all(bind=session_factory.kw["bind"])
    yield
    metadata.drop_all(bind=session_factory.kw["bind"])


@pytest.fixture
@pytest.mark.usefixtures("setup_database")
def db_session():
    from cognito_emulator.db import session_factory

    session = session_factory()
    try:
        yield session
    finally:
        session.close()


class SessionEndpoint(HTTPEndpoint):
    async def patch(self, req: Request) -> JSONResponse:
        req.session.update(await req.json())
        return JSONResponse({})

    async def delete(self, req: Request) -> JSONResponse:
        req.session.clear()
        return JSONResponse({})


@pytest.fixture(
    params=[
        ("RS256", "RSA1_5", "A128CBC-HS256"),
        ("RS256", "RSA-OAEP", "A128CBC-HS256"),
        ("ES384", "ES384", None),
        ("HS256", "A128KW", "A128CBC-HS256"),
    ]
)
def jose_algorithm(request):
    return request.param


@pytest.fixture
def jwt_key(jose_algorithm):
    from ..utils import generate_jwk

    jwk = generate_jwk(jose_algorithm[0])
    logger.info(f"generated JWK: {json.dumps(jwk)}")
    return jwk


@pytest.fixture
def jwt_public_key(jose_algorithm, jwt_key):
    if jose_algorithm[0].lower().startswith("hs"):
        return jwt_key
    else:
        from ..utils import build_jwt_public_key_from_private_key

        return build_jwt_public_key_from_private_key(jwt_key)


@pytest.fixture
def app(jwt_key, jose_algorithm):
    from ..application import create_application

    app = create_application(
        database_url="sqlite:///",
        secret_key="SECRET_KEY",
        debug=True,
        max_pool_workers=-1,
        region="ap-northeast-1",
        jwt_key=jwt_key,
        jwt_signature_algorithm=jose_algorithm[0],
        jwt_encryption_algorithm=jose_algorithm[1],
        jwt_encryption_params={"enc": jose_algorithm[2]},
        prepended_routes=[
            Route("/.testing/session", SessionEndpoint),
        ],
    )
    return app


@pytest.fixture
def set_session(secure_client):
    def _(pool_key, user_id):
        resp = secure_client.patch(
            "/.testing/session", json={pool_key: {"user_id": user_id}}
        )
        assert resp.status_code == 200

    yield _
    resp = secure_client.delete("/.testing/session")
    assert resp.status_code == 200


@pytest.fixture
def client(app):
    with TestClient(app, base_url="http://example.com") as client:
        yield client


@pytest.fixture
def secure_client(app):
    with TestClient(app, base_url="https://example.com") as client:
        yield client
