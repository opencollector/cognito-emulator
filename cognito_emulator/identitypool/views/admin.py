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
import pathlib
import typing

import typesystem
from sqlalchemy.orm import exc as orm_exc
from starlette.exceptions import HTTPException
from starlette.responses import RedirectResponse
from starlette.routing import Router
from starlette.status import HTTP_404_NOT_FOUND

from ...db import session
from ...executor import async_
from ...middlewares import WithTemplates
from ...utils import (
    ContextualHandler,
    ContextualHTTPEndpoint,
    Jinja2Forms,
    coalesce_array_notated_keys,
    from_alien_object,
    populate_sqlalchemy_mapped_object_with_schema,
    validate_form,
)
from ..models import Identity, IdentityPool, Provider

logger = logging.getLogger(__name__)
forms = Jinja2Forms(
    directory=str(pathlib.Path(__file__).parent.parent / "templates" / "_typesystem")
)
routes = Router()


class AdminHTTPEndpoint(ContextualHTTPEndpoint):
    pools: typing.List[IdentityPool]

    @property
    def templates(self):
        return lambda name, context={}, *args, **kwargs: (
            typing.cast(WithTemplates, self.request).templates(
                name,
                {**context, "pools": self.pools},
                *args,
                **kwargs,
            )
        )

    async def post_get_handler_hook(
        self, handler: ContextualHandler
    ) -> ContextualHandler:
        handler = await super().post_get_handler_hook(handler)
        self.pools = await async_(lambda: session.query(IdentityPool).all())()
        return handler


@routes.route("/", name="index")
class IndexEndpoint(AdminHTTPEndpoint):
    async def get(self):
        return self.templates("admin/index.html")


pool_routes = Router()
routes.mount("/{pool}", pool_routes, name="pool")


class AdminPoolHTTPEndpoint(AdminHTTPEndpoint):
    pool: typing.Optional[IdentityPool]
    allow_plus: bool = False

    @property
    def templates(self):
        s = super()
        return lambda name, context={}, *args, **kwargs: (
            s.templates(
                name,
                {**context, "pool": self.pool},
                *args,
                **kwargs,
            )
        )

    async def post_get_handler_hook(
        self, handler: ContextualHandler
    ) -> ContextualHandler:
        handler = await super().post_get_handler_hook(handler)
        key = self.request.path_params["pool"]
        pool: typing.Optional[IdentityPool]
        if key == "+":
            if not self.allow_plus:
                raise HTTPException(status_code=HTTP_404_NOT_FOUND)
            pool = None
        else:
            try:
                pool = await async_(
                    lambda: session.query(IdentityPool).filter_by(key=key).one()
                )()
            except orm_exc.NoResultFound:
                raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        self.pool = pool
        return handler


@pool_routes.route("/", name="index")
class PoolIndexEndpoint(AdminPoolHTTPEndpoint):
    async def get(self):
        return self.templates("admin/pool/index.html")


class IdentityPoolSchema(typesystem.Schema):
    name = typesystem.String(title="Name")
    allow_unauthenticated_identities = typesystem.Boolean(
        title="Allow unauthenticated identities?"
    )


@pool_routes.route("/edit", name="edit")
class PoolEditEndpoint(AdminPoolHTTPEndpoint):
    template = "admin/pool/edit.html"
    allow_plus = True

    async def get(self):
        if self.pool is None:
            values = IdentityPoolSchema()
        else:
            values = from_alien_object(IdentityPoolSchema, self.pool)
        form = forms.Form(IdentityPoolSchema, values=values)
        return self.templates(self.template, {"form": form})

    async def post(self):
        raw_values = coalesce_array_notated_keys(
            (await self.request.form()).multi_items()
        )
        try:
            values = validate_form(IdentityPoolSchema, raw_values)
        except typesystem.ValidationError as e:
            form = forms.Form(IdentityPoolSchema, values=raw_values, errors=e)
            return self.templates(self.template, {"form": form})
        new_pool = await populate_sqlalchemy_mapped_object_with_schema(
            IdentityPool, self.pool, values
        )
        if self.pool is None:
            new_pool.key = self.request.app.state.uuidgen()
            session.add(new_pool)
        await async_(session.commit)()
        return RedirectResponse(
            self.request.url_for(
                "admin:pool:index",
                pool=new_pool.key,
            ),
            status_code=302,
        )


identities_routes = Router()
pool_routes.mount("/identities", identities_routes, name="identities")


@identities_routes.route("/", name="index")
class IdentitiesIndexEndpoint(AdminPoolHTTPEndpoint):
    async def get(self):
        if self.pool is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        identities = await async_(
            lambda: session.query(Identity).filter_by(pool=self.pool).all()
        )()
        return self.templates("admin/pool/identities.html", {"identities": identities})


identity_routes = Router()
identities_routes.mount("/{identity}", identity_routes, name="identity")


class AdminIdentityHTTPEndpoint(AdminPoolHTTPEndpoint):
    identity: typing.Optional[Identity]

    @property
    def templates(self):
        s = super()
        return lambda name, context={}, *args, **kwargs: (
            s.templates(
                name,
                {**context, "identity": self.identity},
                *args,
                **kwargs,
            )
        )

    async def post_get_handler_hook(
        self, handler: ContextualHandler
    ) -> ContextualHandler:
        handler = await super().post_get_handler_hook(handler)
        if self.pool is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        key = self.request.path_params["identity"]
        identity: typing.Optional[Identity] = None
        if key == "+":
            identity = None
        else:
            try:
                identity = await async_(
                    lambda: session.query(Identity)
                    .filter_by(pool=self.pool, key=key)
                    .one()
                )()
            except orm_exc.NoResultFound:
                raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        self.identity = identity
        return handler


providers_routes = Router()
pool_routes.mount("/providers", providers_routes, name="providers")


@providers_routes.route("/", name="index")
class ProvidersIndexEndpoint(AdminPoolHTTPEndpoint):
    async def get(self):
        if self.pool is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        providers = await async_(
            lambda: session.query(Provider).filter_by(pool=self.pool).all()
        )()
        return self.templates("admin/pool/providers.html", {"providers": providers})


provider_routes = Router()
providers_routes.mount("/{provider}", provider_routes, name="provider")


class AdminProviderHTTPEndpoint(AdminPoolHTTPEndpoint):
    provider: typing.Optional[Provider]

    @property
    def templates(self):
        s = super()
        return lambda name, context={}, *args, **kwargs: (
            s.templates(
                name,
                {**context, "provider": self.provider},
                *args,
                **kwargs,
            )
        )

    async def post_get_handler_hook(
        self, handler: ContextualHandler
    ) -> ContextualHandler:
        handler = await super().post_get_handler_hook(handler)
        if self.pool is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        name = self.request.path_params["provider"]
        provider: typing.Optional[Provider] = None
        if name == "+":
            provider = None
        else:
            try:
                provider = await async_(
                    lambda: session.query(Provider)
                    .filter(Provider.pool == self.pool, Provider.url_safe_name == name)
                    .one()
                )()
            except orm_exc.NoResultFound:
                raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        self.provider = provider
        return handler


class ProviderSchema(typesystem.Schema):
    name = typesystem.String(title="Name")
    client_id = typesystem.String(title="Client ID")
    server_side_token_check = typesystem.Boolean(title="Verify tokens on server side?")


@provider_routes.route("/", name="edit")
class ProviderEditEndpoint(AdminProviderHTTPEndpoint):
    template = "admin/pool/provider/edit.html"

    async def get(self):
        if self.provider is None:
            values = ProviderSchema()
        else:
            values = from_alien_object(ProviderSchema, self.provider)
        form = forms.Form(ProviderSchema, values=values)
        return self.templates(self.template, {"form": form})

    async def post(self):
        raw_values = coalesce_array_notated_keys(
            (await self.request.form()).multi_items()
        )
        try:
            values = validate_form(ProviderSchema, raw_values)
        except typesystem.ValidationError as e:
            form = forms.Form(ProviderSchema, values=raw_values, errors=e)
            return self.templates(self.template, {"form": form})
        new_provider = await populate_sqlalchemy_mapped_object_with_schema(
            Provider, self.provider, values
        )
        if self.provider is None:
            new_provider.pool = self.pool
            session.add(new_provider)
        await async_(session.commit)()
        return RedirectResponse(
            self.request.url_for(
                "admin:pool:providers:index",
                pool=self.pool.key,
            ),
            status_code=302,
        )
