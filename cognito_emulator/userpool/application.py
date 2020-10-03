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

import concurrent.futures
import logging
import pathlib
import typing
import uuid
from datetime import timedelta

import sqlalchemy as sa  # type: ignore
from argon2 import PasswordHasher  # type: ignore
from sqlalchemy.orm import exc as orm_exc  # type: ignore
from starlette.applications import Starlette
from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import HTTPConnection
from starlette.routing import BaseRoute, Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.types import ASGIApp, Receive, Scope, Send

from .. import executor
from ..auth import StarletteUserWrapper
from ..db import SQLAlchemyMiddleware, session, session_factory
from ..executor import async_
from ..middlewares import (
    RequestTimeMiddleware,
    TemplateShortcutMiddleware,
    apply_middlewares,
)
from ..utils import generate_key
from .models import User, UserPool
from .oidc import JWKRepr, JWTConfiguration
from .utils import build_jwt_public_key_from_private_key, generate_jwk

POOL_KEY = __name__ + ".pool"

logger = logging.getLogger(__name__)
basedir = pathlib.Path(__file__).parent


class PoolDetectionMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] not in ["http", "websocket"]:
            await self.app(scope, receive, send)
            return

        try:
            pool = await async_(
                lambda: session.query(UserPool)
                .filter_by(key=scope["path_params"]["pool"])
                .one()
            )()
        except orm_exc.NoResultFound:
            pool = None

        scope[POOL_KEY] = pool
        logger.debug(f"pool={pool.key if pool is not None else '(none)'}")
        await self.app(scope, receive, send)


class SessionAuthenticationBackend(AuthenticationBackend):
    async def authenticate(
        self, request: HTTPConnection
    ) -> typing.Optional[typing.Tuple[AuthCredentials, BaseUser]]:
        pool = request.scope[POOL_KEY]
        if pool is not None:
            per_pool_session = request.scope["session"].get(pool.key, {})
        else:
            per_pool_session = request.scope["session"]
        user_id = per_pool_session.get("user_id")
        if user_id is None:
            return None
        logger.debug(f"user_id={user_id}")
        try:
            user = await async_(
                lambda: session.query(User).filter_by(id=user_id).one()
            )()
        except orm_exc.NoResultFound:
            return None
        return AuthCredentials(["authenticated"]), StarletteUserWrapper(user)


def create_application(
    database_url: str,
    secret_key: str,
    jwt_key: typing.Union[None, bytes, JWKRepr] = None,
    jwt_signature_algorithm: str = "RS256",
    jwt_signature_params: typing.Dict[str, str] = {},
    jwt_encryption_algorithm: str = "RS256",
    jwt_encryption_params: typing.Dict[str, str] = {},
    debug: bool = False,
    max_pool_workers: int = 10,
    jwt_ttl: timedelta = timedelta(seconds=3600),
    region: str = "mars-east-1",
    prepended_routes: typing.Iterable[BaseRoute] = [],
):
    from .views import admin as admin_views
    from .views import index as index_views
    from .views import oauth2 as oauth2_views
    from .views import pools as pools_views

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        force=True,
    )
    if max_pool_workers > 0:
        executor.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_pool_workers
        )
    session_factory.configure(
        bind=sa.create_engine(database_url),
    )

    if jwt_key is None:
        jwt_key = generate_jwk(jwt_encryption_algorithm)

    jwt_public_key = jwt_key

    if isinstance(jwt_key, dict):
        if "kid" not in jwt_key:
            jwt_key = dict(jwt_key)
            jwt_key["kid"] = generate_key(16)
        jwt_public_key = build_jwt_public_key_from_private_key(jwt_key)

    jwt_config = JWTConfiguration(
        key=jwt_key,
        public_key=jwt_public_key,
        signature_algorithm=jwt_signature_algorithm,
        signature_params=jwt_signature_params,
        encryption_algorithm=jwt_encryption_algorithm,
        encryption_params=jwt_encryption_params,
        issuer="",
        ttl=jwt_ttl,
    )

    routes: typing.List[BaseRoute] = list(prepended_routes)
    routes += [
        Mount(
            "/static",
            app=StaticFiles(directory=str(basedir / "static")),
            name="static",
        ),
        Mount(
            "/admin",
            name="admin",
            app=admin_views.routes,
        ),
        Mount(
            "/oauth2",
            name="oauth2",
            app=oauth2_views.routes,
        ),
        Route(
            "/logout",
            oauth2_views.LogoutEndpoint,
        ),
        Mount(
            "/{pool}",
            name="pools",
            app=apply_middlewares(
                pools_views.routes,
                middleware=[
                    Middleware(PoolDetectionMiddleware),
                    Middleware(
                        AuthenticationMiddleware, backend=SessionAuthenticationBackend()
                    ),
                ],
            ),
        ),
        Mount("/", index_views.routes),
    ]

    app = Starlette(
        debug=debug,
        routes=routes,
        middleware=[
            Middleware(RequestTimeMiddleware),
            Middleware(SQLAlchemyMiddleware),
            Middleware(SessionMiddleware, secret_key=secret_key),
            Middleware(TemplateShortcutMiddleware),
        ],
        on_shutdown=[
            lambda: (
                executor.executor.shutdown(wait=True)
                if executor.executor is not None
                else None
            ),
        ],
    )
    app.state.jwt_config = jwt_config
    app.state.region = region
    app.state.templates = Jinja2Templates(directory=str(basedir / "templates"))
    app.state.kdf = PasswordHasher()
    app.state.uuidgen = lambda: str(uuid.uuid4())
    return app
