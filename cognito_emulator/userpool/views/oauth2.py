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

import dataclasses
import logging
import re
import typing
from urllib.parse import urlencode, urlparse, urlunparse

from sqlalchemy.orm import exc as orm_exc  # type: ignore
from starlette.authentication import requires
from starlette.endpoints import HTTPEndpoint
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Router
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND

from ...db import session
from ...executor import async_
from ...middlewares import NOW_KEY, WithTemplates
from ...utils import authenticate_by
from ..models import Client, Event, User, UserPool
from ..oidc import (
    EVENT_KEY,
    ClientModelWrapper,
    OAuth2AuthenticationBackend,
    OpenIDCodeMixin,
    OpenIDConnectIdProvider,
    UserModelWrapper,
    get_client_at_authorization_endpoint,
    get_client_at_token_endpoint,
)

logger = logging.getLogger(__name__)
routes = Router()


def build_issuer_url(region: str, pool: UserPool) -> str:
    return f"https://cognito-idp.{region}.amazonaws.com/{pool.key}"


def get_id_provider(
    request: Request, client: ClientModelWrapper
) -> OpenIDConnectIdProvider:
    jwt_config = request.app.state.jwt_config
    if client is not None:
        jwt_config = dataclasses.replace(
            jwt_config,
            issuer=build_issuer_url(request.app.state.region, client.obj.pool),
        )
    return OpenIDConnectIdProvider(
        jwt_config,
        now=lambda: request.scope[NOW_KEY],
        uuidgen=request.app.state.uuidgen,
    )


def new_event(request: Request, pool: UserPool, type_: str) -> Event:
    event = Event(
        pool=pool,
        created_at=request.scope[NOW_KEY],  # type: ignore
        key=request.app.state.uuidgen(),
    )
    session.add(event)
    session.commit()
    return event


def user_for_session(
    session_: typing.Dict[str, typing.Any], pool: UserPool
) -> typing.Optional[User]:
    if pool is not None:
        per_pool_session = session_.get(pool.key, {})
    else:
        per_pool_session = session_
    user_id = per_pool_session.get("user_id")
    if user_id is None:
        return None
    try:
        return session.query(User).filter_by(id=user_id).one()
    except orm_exc.NoResultFound:
        return None


@routes.route("/authorize")
class AuthorizationEndpoint(HTTPEndpoint):
    async def get(self, request: Request) -> Response:
        logger.debug("authorization")
        client_wrap = await async_(get_client_at_authorization_endpoint)(request)
        if client_wrap is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        user: typing.Optional[User] = await async_(user_for_session)(
            request.session, client_wrap.obj.pool
        )
        logger.debug(f"user={user}")
        prompt = request.query_params.get("prompt")
        if prompt is None or prompt != "none":
            if user is None:
                return RedirectResponse(
                    request.url_for("pools:signin", pool=client_wrap.obj.pool.key)
                    + "?"
                    + urlencode({"back_to": str(request.url)})
                )
        request.scope[EVENT_KEY] = (
            await async_(new_event)(request, client_wrap.obj.pool, "authorization")
            if client_wrap is not None
            else None
        )
        id_provider = await async_(get_id_provider)(request, client_wrap)
        return await id_provider.create_authorization_response(request, user)


def only_scheme_and_host_part(uri: str) -> str:
    parsed_uri = urlparse(uri)
    return urlunparse(
        (
            parsed_uri.scheme,
            (
                f"{parsed_uri.hostname}"
                f"{':' if parsed_uri.port is not None else ''}"
                f"{parsed_uri.port if parsed_uri.port is not None else ''}"
            ),
            "",
            "",
            "",
            "",
        )
    )


def append_cors_header_if_valid(
    request: Request, response: Response, allowed_origins: typing.Set[str]
) -> Response:
    origin = request.headers.get("Origin")
    if origin is None:
        return response
    try:
        validated_origin = only_scheme_and_host_part(origin)
    except ValueError:
        logger.info("failed to parse Origin header: {origin}")
        return response
    if validated_origin in allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = validated_origin
        response.headers["Vary"] = ", ".join(
            c for c in re.split(r"\s+,\s+", response.headers.get("Vary", "")) if c != ""
        )
    return response


@routes.route("/token")
class TokenEndpoint(HTTPEndpoint):
    async def post(self, request: Request) -> Response:
        logger.debug("token")
        client_wrap = await async_(get_client_at_token_endpoint)(request)
        request.scope[EVENT_KEY] = (
            await async_(new_event)(request, client_wrap.obj.pool, "token")
            if client_wrap is not None
            else None
        )
        id_provider = await async_(get_id_provider)(request, client_wrap)
        resp = await id_provider.create_token_response(request)
        if client_wrap is None:
            return resp
        return append_cors_header_if_valid(
            request,
            resp,
            {only_scheme_and_host_part(uri) for uri in client_wrap.obj.redirect_uris},
        )


@routes.route("/userInfo")
@authenticate_by(OAuth2AuthenticationBackend())
class UserInfoEndpoint(HTTPEndpoint):
    @requires(["openid", "email", "profile"])
    async def get(self, request):
        return JSONResponse(
            OpenIDCodeMixin.generate_user_info(
                None, UserModelWrapper(request.user.obj), request.auth.scopes
            )
        )


class LogoutEndpoint(HTTPEndpoint):
    async def get(self, request):
        client_id = request.query_params.get("client_id")
        if client_id is None:
            raise HTTPException(status_code=HTTP_400_BAD_REQUEST)
        try:
            client = await async_(
                session.query(Client).filter_by(oauth2_client_id=client_id).one
            )()
        except orm_exc.NoResultFound as e:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND) from e
        logout_uri = request.query_params.get("logout_uri")
        if logout_uri is not None:
            if logout_uri not in client.logout_uris:
                raise HTTPException(status_code=HTTP_400_BAD_REQUEST)

        return typing.cast(WithTemplates, request).templates(
            "logout.html",
            context={"pool": client.pool, "client": client, "back_to": logout_uri},
        )
