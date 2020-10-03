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

import datetime
import json
import os
from base64 import urlsafe_b64encode
from urllib.parse import parse_qs, quote, urlparse

import pytest
from authlib.jose.rfc7519 import JsonWebToken  # type: ignore


@pytest.fixture
def pool(db_session):
    from ..models import UserPool

    return UserPool(
        name="pool",
        key="012345678",
    )


@pytest.fixture
def client(db_session, pool):
    from ..models import Client

    client = Client(
        pool=pool,
        name="pool",
        oauth2_client_id="client_id",
        oauth2_client_secret="client_secret",
        redirect_uris=[
            "https://client.example.com/.testing/callback",
            "https://client.example.com/.testing/another-callback",
        ],
        logout_uris=[
            "https://client.example.com/.testing/logout-uri",
            "https://client.example.com/.testing/another-logout-uri",
        ],
        scopes=["a", "b", "c", "openid"],
    )
    db_session.add(client)
    db_session.commit()
    return client


@pytest.fixture
def user(db_session, pool):
    from ..models import User

    user = User(
        pool=pool,
        name="name",
        key="xxx",
        password="",
        email="email@example.com",
        email_verified=True,
        cognito_mfa_enabled=False,
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def event_obj(db_session, pool):
    from ..models import Event

    event = Event(
        pool=pool,
        created_at=datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc),
    )
    db_session.add(event)
    db_session.commit()
    return event


@pytest.fixture
def code(db_session, pool, client, user, event_obj):
    from ..models import AuthorizationCode

    authz_code = AuthorizationCode(
        pool=pool,
        client=client,
        user=user,
        event=event_obj,
        code="code",
        scope="a b",
        redirect_uri="https://client.example.com/.testing/callback",
    )
    db_session.add(authz_code)
    db_session.commit()
    return authz_code


@pytest.fixture
def code_openid(db_session, pool, client, user, event_obj):
    from ..models import AuthorizationCode

    authz_code = AuthorizationCode(
        pool=pool,
        client=client,
        user=user,
        event=event_obj,
        code="code_openid",
        scope="a b openid",
        redirect_uri="https://client.example.com/.testing/callback",
        nonce="nonce",
    )
    db_session.add(authz_code)
    db_session.commit()
    return authz_code


@pytest.fixture
def code_pkce(db_session, pool, client, user, event_obj, code_verifier_and_challenge):
    from ..models import AuthorizationCode

    code_challenge_method, _, code_challenge = code_verifier_and_challenge

    authz_code = AuthorizationCode(
        pool=pool,
        client=client,
        user=user,
        event=event_obj,
        code="code",
        scope="a b",
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        redirect_uri="https://client.example.com/.testing/callback",
    )
    db_session.add(authz_code)
    db_session.commit()
    return authz_code


@pytest.fixture(params=["plain", "S256"])
def code_challenge_method(request):
    return request.param


@pytest.fixture
def code_verifier_and_challenge(code_challenge_method):
    from authlib.oauth2.rfc7636 import create_s256_code_challenge  # type: ignore

    code_verifier = urlsafe_b64encode(os.urandom(33)).decode("utf-8")

    if code_challenge_method == "plain":
        return code_challenge_method, code_verifier, code_verifier
    elif code_challenge_method == "S256":
        return (
            code_challenge_method,
            code_verifier,
            create_s256_code_challenge(code_verifier),
        )
    else:
        raise AssertionError


def test_default_redirect_uri(secure_client, db_session, user, client, set_session):
    from ..models import AuthorizationCode

    set_session(client.pool.key, user.id)
    resp = secure_client.get(
        f"/oauth2/authorization?client_id={quote(client.oauth2_client_id)}&response_type=code",
        allow_redirects=False,
    )
    assert resp.status_code == 302, resp.content
    parsed_location = urlparse(resp.headers["Location"])
    assert parsed_location.path == "/.testing/callback"
    qs = parse_qs(parsed_location.query)
    assert parsed_location.path == "/.testing/callback"
    code = qs.get("code")
    assert code, parsed_location

    authz_code = (
        db_session.query(AuthorizationCode).filter_by(client=client, code=code[0]).one()
    )
    assert authz_code.user == user


def test_primary_redirect_uri(secure_client, db_session, user, client, set_session):
    from ..models import AuthorizationCode

    set_session(client.pool.key, user.id)
    resp = secure_client.get(
        f"/oauth2/authorization?"
        f"client_id={quote(client.oauth2_client_id)}"
        f"&response_type=code"
        f"&redirect_uri={quote('https://client.example.com/.testing/callback')}",
        allow_redirects=False,
    )
    assert resp.status_code == 302, resp.content
    parsed_location = urlparse(resp.headers["Location"])
    assert parsed_location.path == "/.testing/callback"
    qs = parse_qs(parsed_location.query)
    assert parsed_location.path == "/.testing/callback"
    code = qs.get("code")
    assert code, parsed_location

    authz_code = (
        db_session.query(AuthorizationCode).filter_by(client=client, code=code[0]).one()
    )
    assert authz_code.user == user


def test_secondary_redirect_uri(secure_client, db_session, user, client, set_session):
    from ..models import AuthorizationCode

    set_session(client.pool.key, user.id)
    resp = secure_client.get(
        f"/oauth2/authorization?"
        f"client_id={quote(client.oauth2_client_id)}"
        f"&response_type=code"
        f"&redirect_uri={quote('https://client.example.com/.testing/another-callback')}",
        allow_redirects=False,
    )
    assert resp.status_code == 302, resp.content
    parsed_location = urlparse(resp.headers["Location"])
    assert parsed_location.path == "/.testing/another-callback"
    qs = parse_qs(parsed_location.query)
    code = qs.get("code")
    assert code, parsed_location

    authz_code = (
        db_session.query(AuthorizationCode).filter_by(client=client, code=code[0]).one()
    )
    assert authz_code.user == user


def test_bad_redirect_uri(secure_client, user, client, set_session):
    set_session(client.pool.key, user.id)
    resp = secure_client.get(
        f"/oauth2/authorization?"
        f"client_id={quote(client.oauth2_client_id)}"
        f"&response_type=code"
        f"&redirect_uri={quote('https://client.example.com/.testing/wrong-callback')}",
        allow_redirects=False,
    )
    assert resp.status_code == 400, resp.content


def test_authorization_pkce(
    secure_client, db_session, user, client, set_session, code_verifier_and_challenge
):
    from ..models import AuthorizationCode

    code_challenge_method, code_verifier, code_challenge = code_verifier_and_challenge

    set_session(client.pool.key, user.id)
    resp = secure_client.get(
        f"/oauth2/authorization?"
        f"client_id={quote(client.oauth2_client_id)}"
        f"&response_type=code"
        f"&redirect_uri={quote('https://client.example.com/.testing/callback')}"
        f"&code_challenge={quote(code_challenge)}"
        f"&code_challenge_method={code_challenge_method}",
        allow_redirects=False,
    )
    assert resp.status_code == 302, (resp.headers, resp.content)
    parsed_location = urlparse(resp.headers["Location"])
    assert parsed_location.path == "/.testing/callback"
    qs = parse_qs(parsed_location.query)
    assert parsed_location.path == "/.testing/callback"
    code = qs.get("code")
    assert code, parsed_location

    authz_code = (
        db_session.query(AuthorizationCode).filter_by(client=client, code=code[0]).one()
    )
    assert authz_code.user == user
    assert authz_code.code_challenge == code_challenge
    assert authz_code.code_challenge_method == code_challenge_method


def test_token_endpoint_no_openid(secure_client, user, client, code):
    resp = secure_client.post(
        "/oauth2/token",
        auth=(client.oauth2_client_id, client.oauth2_client_secret),
        data={
            "grant_type": "authorization_code",
            "code": code.code,
            "redirect_uri": "https://client.example.com/.testing/callback",
        },
    )
    assert resp.status_code == 200, resp.content
    assert resp.headers["Content-Type"].startswith("application/json")
    payload = json.loads(resp.content)
    assert set(payload["scope"].split(" ")) == {"a", "b"}
    assert "id_token" not in payload


def test_token_endpoint_no_openid_no_authz_header(secure_client, user, client, code):
    resp = secure_client.post(
        "/oauth2/token",
        data={
            "client_id": client.oauth2_client_id,
            "client_secret": client.oauth2_client_secret,
            "grant_type": "authorization_code",
            "code": code.code,
            "redirect_uri": "https://client.example.com/.testing/callback",
        },
    )
    assert resp.status_code == 200, resp.content
    assert resp.headers["Content-Type"].startswith("application/json")
    payload = json.loads(resp.content)
    assert set(payload["scope"].split(" ")) == {"a", "b"}
    assert "id_token" not in payload


def test_token_endpoint_openid(
    secure_client, user, client, code_openid, jwt_public_key
):
    resp = secure_client.post(
        "/oauth2/token",
        auth=(client.oauth2_client_id, client.oauth2_client_secret),
        data={
            "grant_type": "authorization_code",
            "code": code_openid.code,
            "redirect_uri": "https://client.example.com/.testing/callback",
        },
    )
    assert resp.status_code == 200, resp.content
    assert resp.headers["Content-Type"].startswith("application/json")
    payload = json.loads(resp.content)
    assert set(payload["scope"].split(" ")) == {"a", "b", "openid"}
    assert "id_token" in payload
    id_token_payload = JsonWebToken().decode(payload["id_token"], jwt_public_key)
    assert id_token_payload != "", id_token_payload


def test_token_endpoint_pkce(
    secure_client, user, client, code_pkce, code_verifier_and_challenge
):
    _, code_verifier, _ = code_verifier_and_challenge
    resp = secure_client.post(
        "/oauth2/token",
        auth=(client.oauth2_client_id, client.oauth2_client_secret),
        data={
            "grant_type": "authorization_code",
            "code": code_pkce.code,
            "redirect_uri": "https://client.example.com/.testing/callback",
            "code_verifier": code_verifier,
        },
    )
    assert resp.status_code == 200, resp.content
    assert resp.headers["Content-Type"].startswith("application/json")
    payload = json.loads(resp.content)
    assert set(payload["scope"].split(" ")) == {"a", "b"}


def test_logout_endpoint_without_client_id(secure_client, user, client, set_session):
    set_session(client.pool.key, user.id)

    resp = secure_client.get("/logout")
    assert resp.status_code == 400, resp.content


def test_logout_endpoint_invalid_client_id(secure_client, user, client, set_session):
    set_session(client.pool.key, user.id)

    resp = secure_client.get("/logout?client_id=INVALID")
    assert resp.status_code == 404, resp.content


def test_logout_endpoint_valid_client_id_without_logout_uri(
    secure_client, user, client, set_session
):
    set_session(client.pool.key, user.id)

    resp = secure_client.get(f"/logout?client_id={client.oauth2_client_id}")
    assert resp.status_code == 200, resp.content
