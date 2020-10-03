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

import logging
import re
import typing
import uuid

import httpx
import sqlalchemy as sa
import typesystem
from async_lru import alru_cache  # type: ignore
from authlib.jose import JoseError, JsonWebKey, JsonWebToken, KeySet  # type: ignore
from sqlalchemy.orm import exc as orm_exc
from starlette.requests import Request

from ...db import session
from ...endpoints import (
    AWSLikeEndpoint,
    AWSPayload,
    AWSPayloadResponse,
    AWSServerException,
    amz_target,
)
from ...executor import async_
from ...middlewares import NOW_KEY
from ..models import Identity, IdentityPool, Login, Provider

logger = logging.getLogger(__name__)


LEEWAY = 600


class GetIdRequest(typesystem.Schema):
    AccountId = typesystem.String(
        min_length=1, max_length=15, pattern=r"^\d+$", allow_null=True
    )
    IdentityPoolId = typesystem.String(
        min_length=1, max_length=55, pattern=r"^[\w-]+:[0-9a-f-]+$"
    )
    Logins = typesystem.Object(allow_null=False)


class GetIdResponse(typesystem.Schema):
    IdentityId = typesystem.String(
        min_length=1, max_length=55, pattern=r"^[\w-]+:[0-9a-f-]+$"
    )


class InvalidParameterException(AWSServerException):
    message: typing.Optional[str]

    def __init__(self, message: typing.Optional[str] = None):
        super().__init__()
        self.message = message

    def as_aws_payload(self) -> AWSPayload:
        return {
            "__type": "InvalidParameterException",
            "message": self.message,
        }


class NotAuthorizedException(AWSServerException):
    message: typing.Optional[str]

    def __init__(self, message: typing.Optional[str] = None):
        super().__init__()
        self.message = message

    def as_aws_payload(self) -> AWSPayload:
        return {
            "__type": "NotAuthorizedException",
            "message": self.message,
        }


class ResourceNotFoundException(AWSServerException):
    message: typing.Optional[str]

    def __init__(self, message: typing.Optional[str] = None):
        super().__init__()
        self.message = message

    def as_aws_payload(self) -> AWSPayload:
        return {
            "__type": "ResourceNotFoundException",
            "message": self.message,
        }


class ResourceConflictException(AWSServerException):
    message: typing.Optional[str]

    def __init__(self, message: typing.Optional[str] = None):
        super().__init__()
        self.message = message

    def as_aws_payload(self) -> AWSPayload:
        return {
            "__type": "ResourceConflictException",
            "message": self.message,
        }


@alru_cache(maxsize=5)
async def get_jwks(url: str) -> KeySet:
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return JsonWebKey.import_key_set(resp.json())


COGNITO_IDP_ENDPOINT_URL_RE = re.compile(
    r"cognito-idp.(?P<region>[^.]+).amazonaws.com/(?P<pool_id>[^/]+)"
)


async def get_subject_by_provider(
    request: Request, provider_name: str, token_str: str
) -> str:
    m = COGNITO_IDP_ENDPOINT_URL_RE.match(provider_name)
    if m is not None:
        url_base = (
            request.app.state.user_pool_emulator_url_base.rstrip("/")
            + "/"
            + m.group("pool_id")
        )
        try:
            jwks = await get_jwks(f"{url_base}/.well-known/jwks.json")
            token = JsonWebToken().decode(token_str, key=jwks)
            token.validate_iss()
            token.validate_sub()
            token.validate_exp(request.scope[NOW_KEY].timestamp(), LEEWAY)
        except (httpx.HTTPError, JoseError):
            logger.error("failed to validate token", exc_info=True)
            raise NotAuthorizedException(
                "Invalid login token. Not a valid OpenId Connect identity token."
            )
        return token["sub"]
    else:
        raise NotImplementedError()


async def get_or_create_identity(
    request: Request, pool: IdentityPool, logins: typing.Mapping[str, str]
) -> Identity:
    q = (
        session.query(Identity)
        .join(Identity.logins)
        .join(Login.provider)
        .filter(Identity.pool == pool)
    )
    op: typing.Optional[sa.sql.operators.Operators] = None

    provider_subject_map: typing.Mapping[str, str] = {
        provider_name: await get_subject_by_provider(request, provider_name, token)
        for provider_name, token in logins.items()
    }

    for provider_name in logins.keys():
        subject = provider_subject_map[provider_name]
        new_op = (Provider.name == provider_name) & (Login.subject == subject)
        if op is None:
            op = new_op
        else:
            op |= new_op
    q = q.filter(op)
    identities = await async_(lambda: q.all())()
    if len(identities) == 1:
        return identities[0]
    elif len(identities) > 1:
        raise ResourceConflictException("")

    try:
        region = request.app.state.region
        identity = Identity(
            pool=pool,
            key=f"{region}:{uuid.uuid4()}",
            logins=typing.cast(
                typing.List[Login],
                [
                    Login(
                        pool=pool,
                        provider=await async_(
                            lambda: session.query(Provider)
                            .filter_by(name=provider_name)
                            .one()
                        )(),
                        subject=provider_subject_map[provider_name],
                    )
                    for provider_name in logins.keys()
                ],
            ),
        )
        session.add(identity)
        await async_(lambda: session.commit())()
        return identity
    except orm_exc.NoResultFound:
        raise NotAuthorizedException("Invalid login token.")


class CognitoIdentityEndpoint(AWSLikeEndpoint):
    @amz_target("AWSCognitoIdentityService.GetId")
    async def get_id(self, req_payload: AWSPayload) -> AWSPayloadResponse:
        try:
            get_id_req = typing.cast(GetIdRequest, GetIdRequest.validate(req_payload))
        except typesystem.ValidationError as e:
            raise InvalidParameterException() from e

        pool: typing.Optional[IdentityPool] = None
        region, _, identity_pool_id = get_id_req.IdentityPoolId.partition(":")  # type: ignore
        if region == self.request.app.state.region:
            try:
                pool = await async_(
                    lambda: session.query(IdentityPool)
                    .filter_by(key=identity_pool_id)
                    .with_for_update(read=True)
                    .one()
                )()
            except orm_exc.NoResultFound:
                pass
        if pool is None:
            raise ResourceNotFoundException(
                f"IdentityPool '{get_id_req.IdentityPoolId}' not found."
            )

        identity = await get_or_create_identity(self.request, pool, typing.cast(typing.Mapping[str, str], get_id_req.Logins))

        resp = GetIdResponse(
            IdentityId=identity.key,
        )
        return dict(resp)


endpoint_handler = CognitoIdentityEndpoint
