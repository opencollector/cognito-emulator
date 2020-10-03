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
from sqlalchemy import orm
from sqlalchemy.orm import exc as orm_exc
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Router
from starlette.status import HTTP_404_NOT_FOUND

from ...db import session
from ...executor import async_
from ...middlewares import NOW_KEY, WithTemplates
from ...utils import (
    Choice,
    ContextualHandler,
    ContextualHTTPEndpoint,
    Jinja2Forms,
    ObjectChoice,
    coalesce_array_notated_keys,
    from_alien_object,
    generate_key,
    populate_sqlalchemy_mapped_object_with_schema,
    validate_form,
)
from ..models import (
    AuxiliaryIdentityAttribute,
    Client,
    Event,
    Group,
    User,
    UserIdentityAttribute,
    UserPool,
)
from ..oidc import EVENT_KEY, ClientModelWrapper
from ..types import KeyDerivationFunction
from .oauth2 import build_issuer_url, get_id_provider

logger = logging.getLogger(__name__)
forms = Jinja2Forms(
    directory=str(pathlib.Path(__file__).parent.parent / "templates" / "_typesystem")
)
routes = Router()


class AdminHTTPEndpoint(ContextualHTTPEndpoint):
    pools: typing.List[UserPool]

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
        self.pools = await async_(lambda: session.query(UserPool).all())()
        return handler


@routes.route("/", name="index")
class IndexEndpoint(AdminHTTPEndpoint):
    async def get(self):
        return self.templates("admin/index.html")


pool_routes = Router()
routes.mount("/{pool}", pool_routes, name="pool")


class AdminPoolHTTPEndpoint(AdminHTTPEndpoint):
    pool: typing.Optional[UserPool]
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
        pool: typing.Optional[UserPool]
        if key == "+":
            if not self.allow_plus:
                raise HTTPException(status_code=HTTP_404_NOT_FOUND)
            pool = None
        else:
            try:
                pool = await async_(
                    lambda: session.query(UserPool).filter_by(key=key).one()
                )()
            except orm_exc.NoResultFound:
                raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        self.pool = pool
        return handler


@pool_routes.route("/", name="index")
class PoolIndexEndpoint(AdminPoolHTTPEndpoint):
    async def get(self):
        return self.templates(
            "admin/pool/index.html",
            {"issuer_url": build_issuer_url(self.request.app.state.region, self.pool)},
        )


class UserPoolSchema(typesystem.Schema):
    name = typesystem.String(title="Name")
    alias_attributes = typesystem.Array(
        Choice(title="Alias attributes", choices=UserIdentityAttribute),
        unique_items=True,
        default=[],
    )
    auto_verified_attributes = typesystem.Array(
        Choice(title="Auto-verified attributes", choices=AuxiliaryIdentityAttribute),
        unique_items=True,
        default=[],
    )
    username_attributes = typesystem.Array(
        Choice(
            title="Username attributes (if none selected, username will be used)",
            choices=AuxiliaryIdentityAttribute,
        ),
        unique_items=True,
        default=[],
    )
    username_case_sensitiveness = typesystem.Boolean(
        title=(
            "User names are case sensitive"
            "(e-mail addresses are treated insensitively by default)"
        )
    )


@pool_routes.route("/edit", name="edit")
class PoolEditEndpoint(AdminPoolHTTPEndpoint):
    template = "admin/pool/edit.html"
    allow_plus = True

    async def get(self):
        if self.pool is None:
            values = UserPoolSchema()
        else:
            values = from_alien_object(UserPoolSchema, self.pool)
        form = forms.Form(UserPoolSchema, values=values)
        return self.templates(self.template, {"form": form})

    async def post(self):
        raw_values = coalesce_array_notated_keys(
            (await self.request.form()).multi_items()
        )
        try:
            values = validate_form(UserPoolSchema, raw_values)
        except typesystem.ValidationError as e:
            form = forms.Form(UserPoolSchema, values=raw_values, errors=e)
            return self.templates(self.template, {"form": form})
        new_pool = await populate_sqlalchemy_mapped_object_with_schema(
            UserPool, self.pool, values
        )
        if self.pool is None:
            new_pool.key = self.request.app.state.region + "_" + generate_key(9)
            session.add(new_pool)
        await async_(session.commit)()
        return RedirectResponse(
            self.request.url_for(
                "admin:pool:index",
                pool=new_pool.key,
            ),
            status_code=302,
        )


users_routes = Router()
pool_routes.mount("/users", users_routes, name="users")


@users_routes.route("/", name="index")
class UsersIndexEndpoint(AdminPoolHTTPEndpoint):
    async def get(self):
        if self.pool is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        users = await async_(
            lambda: session.query(User).filter_by(pool=self.pool).all()
        )()
        return self.templates("admin/pool/users.html", {"users": users})


user_routes = Router()
users_routes.mount("/{user}", user_routes, name="user")


class AdminUserHTTPEndpoint(AdminPoolHTTPEndpoint):
    user: typing.Optional[User]

    @property
    def templates(self):
        s = super()
        return lambda name, context={}, *args, **kwargs: (
            s.templates(
                name,
                {**context, "user": self.user},
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
        key = self.request.path_params["user"]
        user: typing.Optional[User] = None
        if key == "+":
            user = None
        else:
            try:
                user = await async_(
                    lambda: session.query(User).filter_by(pool=self.pool, key=key).one()
                )()
            except orm_exc.NoResultFound:
                raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        self.user = user
        return handler


class UserSchema(typesystem.Schema):
    name = typesystem.String(title="Name")
    email = typesystem.String(title="E-mail")
    email_verified = typesystem.Boolean(title="E-mail verified?", default=False)
    given_name = typesystem.String(title="Given name", allow_null=True)
    middle_name = typesystem.String(title="Middle name", allow_null=True)
    family_name = typesystem.String(title="Family name", allow_null=True)
    nickname = typesystem.String(title="Nick name", allow_null=True)
    preferred_username = typesystem.String(title="Preferred user name", allow_null=True)
    profile = typesystem.String(title="Profile", allow_null=True)
    website = typesystem.String(title="Website", allow_null=True)
    gender = typesystem.String(title="Gender", allow_null=True)
    birthdate = typesystem.Date(title="Birthdate", allow_null=True)
    zoneinfo = typesystem.String(title="Zone info", allow_null=True)
    locale = typesystem.String(title="Locale", allow_null=True)
    phone_number = typesystem.String(
        title="Phone number", format="tel", allow_null=True
    )
    phone_number_verified = typesystem.Boolean(
        title="Phone number verified?", allow_null=True
    )
    address = typesystem.String(title="Address", allow_null=True)
    cognito_mfa_enabled = typesystem.Boolean(title="MFA enabled?", default=True)


@user_routes.route("/", name="edit")
class UserEditEndpoint(AdminUserHTTPEndpoint):
    template = "admin/pool/user/edit.html"

    async def get(self):
        if self.user is None:
            values = UserSchema()
        else:
            values = from_alien_object(UserSchema, self.user)
        form = forms.Form(UserSchema, values=values)
        return self.templates(self.template, {"form": form})

    async def post(self):
        raw_values = coalesce_array_notated_keys(
            (await self.request.form()).multi_items()
        )
        try:
            values = validate_form(UserSchema, raw_values)
        except typesystem.ValidationError as e:
            form = forms.Form(UserSchema, values=raw_values, errors=e)
            return self.templates(self.template, {"form": form})
        new_user = await populate_sqlalchemy_mapped_object_with_schema(
            User, self.user, values
        )
        if self.user is None:
            new_user.pool = self.pool
            new_user.key = self.request.app.state.uuidgen()
            new_user.password = ""
            session.add(new_user)
        await async_(session.commit)()
        return RedirectResponse(
            self.request.url_for("admin:pool:users:index", pool=self.pool.key),
            status_code=302,
        )


user_pai_routes = Router()
user_routes.mount("/pai", user_pai_routes, name="pai")


class PAIGenerateTokenSchema(typesystem.Schema):
    client_id = typesystem.String(allow_null=False)
    scope = typesystem.String(allow_null=False)


@user_pai_routes.route("/generate-tokens", name="generate_tokens")
class PAIGenerateTokenEndpoint(AdminUserHTTPEndpoint):
    async def post(self):
        try:
            req = PAIGenerateTokenSchema.validate(await self.request.json())
        except typesystem.ValidationError as e:
            return JSONResponse(
                {"errors": {m.index[0]: m.text for m in e.messages()}}, status_code=400
            )
        client = await async_(
            lambda: session.query(Client)
            .filter_by(pool=self.pool, oauth2_client_id=req.client_id)
            .one()
        )()
        client_wrap = ClientModelWrapper(client)
        id_provider = await async_(get_id_provider)(self.request, client_wrap)
        self.request.scope[EVENT_KEY] = Event(
            pool=self.pool,
            created_at=self.request.scope[NOW_KEY],  # type: ignore
            key=self.request.app.state.uuidgen(),
        )
        token = await id_provider.direct_grant(
            request=self.request,
            client=client_wrap,
            user=self.user,
            scope=" ".join(
                set(req.scope.split(None)) & set(client_wrap.get_scope().split(None))
            ),
        )
        return JSONResponse({"result": token})


@user_pai_routes.route("/list-eligible-clients", name="list_eligible_clients")
class PAIListEligibleClients(AdminUserHTTPEndpoint):
    async def get(self):
        clients = await async_(session.query(Client).filter_by(pool=self.pool).all)()
        return JSONResponse(
            {
                "clients": [
                    {
                        "id": client.id,
                        "name": client.name,
                        "client_id": client.oauth2_client_id,
                        "scope": list(client.scopes),
                    }
                    for client in clients
                ],
            }
        )


class PasswordFormSchema(typesystem.Schema):
    password = typesystem.String(title="Password", allow_null=False, format="password")
    password_confirm = typesystem.String(
        title="Password (confirm)", allow_null=False, format="password"
    )


@user_routes.route("/password", name="change_password")
class UserPasswordEditEndpoint(AdminUserHTTPEndpoint):
    template = "admin/pool/user/change_password.html"

    @property
    def kdf(self) -> KeyDerivationFunction:
        return self.request.app.state.kdf

    async def render_form(
        self,
        values: PasswordFormSchema,
        errors: typing.Optional[typesystem.ValidationError] = None,
    ):
        form = forms.Form(
            values.__class__,
            values=typing.cast(typing.Dict[typing.Any, typing.Any], values),
            errors=errors,
        )
        return self.templates(self.template, {"form": form})

    async def get(self):
        return await self.render_form(PasswordFormSchema())

    async def post(self):
        raw_values = coalesce_array_notated_keys(
            (await self.request.form()).multi_items()
        )
        try:
            values = validate_form(PasswordFormSchema, raw_values)
            if values.password != values.password_confirm:
                raise typesystem.ValidationError(
                    messages=[
                        typesystem.Message(
                            text="Passwords do not match",
                            code="umatching_pair",
                            index=["password", "password_confirm"],
                        )
                    ],
                )
        except typesystem.ValidationError as e:
            return await self.render_form(PasswordFormSchema(), e)
        self.user.password = self.kdf.hash(values.password)
        session.commit()
        return RedirectResponse(
            self.request.url_for(
                "admin:pool:users:user:edit", pool=self.pool.key, user=self.user.key
            ),
            status_code=302,
        )


groups_routes = Router()
pool_routes.mount("/groups", groups_routes, name="groups")


@groups_routes.route("/", name="index")
class GroupsIndexEndpoint(AdminPoolHTTPEndpoint):
    async def get(self):
        groups = await async_(lambda: session.query(Group).all())()
        return self.templates("admin/pool/groups.html", {"groups": groups})


group_routes = Router()
groups_routes.mount("/{group}", group_routes, name="group")


class AdminGroupHTTPEndpoint(AdminPoolHTTPEndpoint):
    group: typing.Optional[Group]

    @property
    def templates(self):
        s = super()
        return lambda name, context={}, *args, **kwargs: (
            s.templates(
                name,
                {**context, "group": self.group},
                *args,
                **kwargs,
            )
        )

    async def post_get_handler_hook(
        self, handler: ContextualHandler
    ) -> ContextualHandler:
        handler = await super().post_get_handler_hook(handler)
        key = self.request.path_params["group"]
        group: typing.Optional[Group] = None
        if key == "+":
            group = None
        else:
            try:
                group = await async_(
                    lambda: session.query(Group)
                    .filter_by(key=key)
                    .options(orm.joinedload("users"))
                    .one()
                )()
            except orm_exc.NoResultFound:
                raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        self.group = group
        return handler


@group_routes.route("/", name="edit")
class GroupEditEndpoint(AdminGroupHTTPEndpoint):
    template = "admin/pool/group/edit.html"

    async def users(self) -> typing.Sequence[User]:
        return await async_(
            lambda: session.query(User).filter_by(pool=self.pool).all()
        )()

    async def group_schema(self) -> typing.Type[typesystem.Schema]:
        _users = await self.users()

        class GroupSchema(typesystem.Schema):
            name = typesystem.String(title="Name")
            users = typesystem.Array(ObjectChoice(choices=_users), title="users")

        return GroupSchema

    async def get(self):
        group_schema = await self.group_schema()
        if self.group is None:
            values = group_schema()
        else:
            values = from_alien_object(group_schema, self.group)
        form = forms.Form(group_schema, values=values)
        return self.templates(self.template, {"form": form})

    async def post(self):
        group_schema = await self.group_schema()
        raw_values = coalesce_array_notated_keys(
            (await self.request.form()).multi_items()
        )
        try:
            values = validate_form(group_schema, raw_values)
        except typesystem.ValidationError as e:
            form = forms.Form(group_schema, values=raw_values, errors=e)
            return self.templates(self.template, {"form": form})
        new_group = await populate_sqlalchemy_mapped_object_with_schema(
            Group,
            self.group,
            values,
            session=session,
        )
        if self.group is None:
            new_group.pool = self.pool
            session.add(new_group)
        await async_(session.commit)()
        return RedirectResponse(
            self.request.url_for(
                "admin:pool:groups:index",
                pool=self.pool.key,
            ),
            status_code=302,
        )


clients_routes = Router()
pool_routes.mount("/clients", clients_routes, name="clients")


@clients_routes.route("/", name="index")
class ClientsIndexEndpoint(AdminPoolHTTPEndpoint):
    async def get(self):
        clients = await async_(
            lambda: session.query(Client).filter_by(pool=self.pool).all()
        )()
        return self.templates("admin/pool/clients.html", {"clients": clients})


client_routes = Router()
clients_routes.mount("/{client}", client_routes, name="client")


class AdminClientHTTPEndpoint(AdminPoolHTTPEndpoint):
    client: typing.Optional[Client]

    @property
    def templates(self):
        s = super()
        return lambda name, context={}, *args, **kwargs: (
            s.templates(
                name,
                {**context, "client": self.client},
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
        key = self.request.path_params["client"]
        client: typing.Optional[Client] = None
        if key == "+":
            client = None
        else:
            try:
                client = await async_(
                    lambda: session.query(Client)
                    .filter_by(pool=self.pool, oauth2_client_id=key)
                    .options(
                        orm.joinedload("_redirect_uris"), orm.joinedload("_scopes")
                    )
                    .one()
                )()
            except orm_exc.NoResultFound:
                raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        self.client = client
        return handler


class ClientSchema(typesystem.Schema):
    name = typesystem.String(title="Name")
    oauth2_client_id = typesystem.String(title="Client ID", allow_null=True)
    oauth2_client_secret = typesystem.String(title="Client secret", allow_null=True)
    ttl_for_authorization_code = typesystem.String(
        title="Authorization code TTL", allow_null=True
    )
    ttl_for_implicit = typesystem.String(title="Implicit token TTL", allow_null=True)
    ttl_for_refresh_token = typesystem.String(
        title="Refresh token TTL", allow_null=True
    )
    authn_max_age = typesystem.String(
        title="OpenID Connect ID token max age", allow_null=True
    )
    redirect_uris = typesystem.Array(typesystem.String(), title="Redirect URIs")
    logout_uris = typesystem.Array(typesystem.String(), title="Logout URIs")
    scopes = typesystem.Array(typesystem.String(), title="Scopes")


@client_routes.route("/", name="edit")
class ClientEditEndpoint(AdminClientHTTPEndpoint):
    template = "admin/pool/client/edit.html"

    async def get(self):
        if self.client is None:
            values = ClientSchema()
        else:
            values = from_alien_object(ClientSchema, self.client)
        form = forms.Form(ClientSchema, values=values)
        return self.templates(self.template, {"form": form})

    async def post(self):
        raw_values = coalesce_array_notated_keys(
            (await self.request.form()).multi_items()
        )
        try:
            values = validate_form(ClientSchema, raw_values)
        except typesystem.ValidationError as e:
            form = forms.Form(ClientSchema, values=raw_values, errors=e)
            return self.templates(self.template, {"form": form})
        new_client = await populate_sqlalchemy_mapped_object_with_schema(
            Client, self.client, values
        )
        if self.client is None:
            new_client.pool = self.pool
            session.add(new_client)
        await async_(session.commit)()
        return RedirectResponse(
            self.request.url_for(
                "admin:pool:clients:index",
                pool=self.pool.key,
            ),
            status_code=302,
        )
