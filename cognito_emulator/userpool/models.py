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

import re
import typing

import sqlalchemy as sa  # type: ignore
from sqlalchemy.engine.default import DefaultExecutionContext  # type: ignore
from sqlalchemy.ext.associationproxy import association_proxy  # type: ignore
from sqlalchemy.sql import functions as sql_func  # type: ignore

from ..db import Base
from ..models import CreatedMixin, CreatedUpdatedMixin
from ..utils import StrEnum, generate_key


class AuxiliaryIdentityAttribute(StrEnum):
    PHONE_NUMBER = "phone_number"
    EMAIL = "email"


class UserIdentityAttribute(StrEnum):
    PHONE_NUMBER = "phone_number"
    EMAIL = "email"
    PREFERRED_USERNAME = "preferred_username"


T = typing.TypeVar("T", bound=StrEnum)


class StrEnumArray(sa.TypeDecorator, typing.Generic[T]):
    impl = sa.String
    enum_type: typing.Type[T]

    def __init__(self, *args, enum_type: typing.Type[T], **kwargs):
        self.enum_type = enum_type
        super().__init__(*args, **kwargs)

    def process_bind_param(
        self, value: typing.Any, dialect: sa.engine.interfaces.Dialect
    ) -> typing.Any:
        return (
            " ".join(typing.cast(typing.Sequence[T], value))
            if value is not None
            else None
        )

    def process_result_value(
        self, value: typing.Any, dialect: sa.engine.interfaces.Dialect
    ) -> typing.Any:
        value_ = typing.cast(str, value).strip()
        if value_ == "":
            return []
        return [self.enum_type(v) for v in re.split(r"\s+", value_)]


class UserPool(Base, CreatedUpdatedMixin):
    __tablename__ = "userpools"

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    name = sa.Column(sa.String(255), nullable=False, unique=True)
    key = sa.Column(sa.String(255), nullable=False)
    alias_attributes = sa.Column(
        StrEnumArray(length=255, enum_type=UserIdentityAttribute),
        nullable=False,
        default=[],
        server_default="",
    )
    auto_verified_attributes = sa.Column(
        StrEnumArray(length=255, enum_type=AuxiliaryIdentityAttribute),
        nullable=False,
        default=[],
        server_default="",
    )
    username_attributes = sa.Column(
        StrEnumArray(length=255, enum_type=AuxiliaryIdentityAttribute),
        nullable=False,
        default=[],
        server_default="",
    )
    username_case_sensitiveness = sa.Column(sa.Boolean(), nullable=False, default=True)

    def query_user(self, username: str) -> sa.orm.Query:
        username_attrs = set(self.username_attributes)
        if username_attrs:
            expr = sa.sql.elements.True_()
            if AuxiliaryIdentityAttribute.EMAIL in username_attrs:
                expr |= (
                    sql_func.func.lower(User.email) == username.lower()
                ) & User.email_verified
            if AuxiliaryIdentityAttribute.PHONE_NUMBER in username_attrs:
                expr |= (User.phone_number == username) & User.phone_number_verified
        else:
            alias_attributes = set(self.alias_attributes)
            expr = User.name == username
            if UserIdentityAttribute.EMAIL in alias_attributes:
                expr |= (
                    sql_func.func.lower(User.email) == username.lower()
                ) & User.email_verified
            if UserIdentityAttribute.PHONE_NUMBER in alias_attributes:
                expr |= (User.phone_number == username) & User.phone_number_verified
            if UserIdentityAttribute.PREFERRED_USERNAME in alias_attributes:
                expr |= User.preferred_username == username
        return self.users.filter(expr)  # type: ignore

    users = sa.orm.relationship(
        "User", back_populates="pool", lazy="dynamic", cascade="all, delete-orphan"
    )
    groups = sa.orm.relationship(
        "Group", back_populates="pool", lazy="dynamic", cascade="all, delete-orphan"
    )
    clients = sa.orm.relationship(
        "Client", back_populates="pool", lazy="dynamic", cascade="all, delete-orphan"
    )

    __table_args__ = (sa.Index("ix_userpools_key", key),)


class Client(Base, CreatedUpdatedMixin):
    __tablename__ = "clients"

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(sa.Integer(), sa.ForeignKey("userpools.id"), nullable=False)
    name = sa.Column(sa.String(255), nullable=False)
    oauth2_client_id = sa.Column(
        sa.String(255), nullable=False, unique=True, default=lambda: generate_key(26)
    )
    oauth2_client_secret = sa.Column(
        sa.String(255), nullable=True, default=lambda: generate_key(51)
    )
    ttl_for_authorization_code = sa.Column(sa.Integer(), nullable=False, default=3600)
    ttl_for_implicit = sa.Column(sa.Integer(), nullable=False, default=1800)
    ttl_for_refresh_token = sa.Column(sa.Integer(), nullable=False, default=3600)
    authn_max_age = sa.Column(sa.Integer(), nullable=False, default=3600)

    _redirect_uris = sa.orm.relationship(
        "ClientRedirectUri",
        order_by="ClientRedirectUri.serial",
        cascade="all, delete-orphan",
    )
    redirect_uris = association_proxy(
        "_redirect_uris", "uri", creator=lambda uri: ClientRedirectUri(uri=uri)  # type: ignore
    )

    _logout_uris = sa.orm.relationship(
        "ClientLogoutUri",
        order_by="ClientLogoutUri.serial",
        cascade="all, delete-orphan",
    )
    logout_uris = association_proxy(
        "_logout_uris", "uri", creator=lambda uri: ClientLogoutUri(uri=uri)  # type: ignore
    )

    _scopes = sa.orm.relationship("ClientAllowedScope", cascade="all, delete-orphan")
    scopes = association_proxy(
        "_scopes", "scope", creator=lambda scope: ClientAllowedScope(scope=scope)  # type: ignore
    )
    pool = sa.orm.relationship(UserPool, back_populates="clients")

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    def get_ttl_for(self, grant_type: str) -> int:
        if grant_type == "authorization_code":
            return self.ttl_for_authorization_code
        elif grant_type == "implicit":
            return self.ttl_for_implicit
        elif grant_type == "refresh_token":
            return self.ttl_for_refresh_token
        else:
            raise ValueError(f"invalid grant type: {grant_type}")


class ClientMemberProtocol(typing.Protocol):
    serial: sa.Column
    client_id: sa.Column


def serial_default(
    class_: typing.Type[ClientMemberProtocol],
) -> typing.Callable[[DefaultExecutionContext], int]:
    def _(context: DefaultExecutionContext):
        result = context.root_connection.execute(  # type: ignore
            sa.select([sql_func.coalesce(sql_func.max(class_.serial), 0) + 1]).where(
                class_.client_id
                == context.get_current_parameters()["client_id"]  # type: ignore
            )
        )
        try:
            return result.fetchone()[0]
        finally:
            result.close()

    return _


def pool_id_default(context: DefaultExecutionContext) -> int:
    result = context.root_connection.execute(  # type: ignore
        sa.select([Client.pool_id]).where(
            Client.id == context.get_current_parameters()["client_id"]  # type: ignore
        )
    )
    try:
        return result.fetchone()[0]
    finally:
        result.close()


class ClientRedirectUri(Base):
    __tablename__ = "client_redirect_uris"
    __table_args__ = (
        # disabled due to SQLAlchemy's current limitation
        # sa.UniqueConstraint("client_id", "uri"),
        sa.UniqueConstraint("client_id", "serial"),
    )

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(
        sa.Integer(),
        sa.ForeignKey(UserPool.id),
        nullable=False,
        default=pool_id_default,
    )
    client_id = sa.Column(sa.Integer(), sa.ForeignKey(Client.id), nullable=False)
    uri = sa.Column(sa.String(255), nullable=False)
    serial = sa.Column(
        sa.Integer(),
        nullable=False,
        default=lambda context: serial_default(ClientRedirectUri)(context),
    )

    client = sa.orm.relationship(Client)


class ClientLogoutUri(Base):
    __tablename__ = "client_logout_uris"
    __table_args__ = (
        # disabled due to SQLAlchemy's current limitation
        # sa.UniqueConstraint("client_id", "uri"),
        sa.UniqueConstraint("client_id", "serial"),
    )

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(
        sa.Integer(),
        sa.ForeignKey(UserPool.id),
        nullable=False,
        default=pool_id_default,
    )
    client_id = sa.Column(sa.Integer(), sa.ForeignKey(Client.id), nullable=False)
    uri = sa.Column(sa.String(255), nullable=False)
    serial = sa.Column(
        sa.Integer(),
        nullable=False,
        default=lambda context: serial_default(ClientLogoutUri)(context),
    )

    client = sa.orm.relationship(Client)


class ClientAllowedScope(Base):
    __tablename__ = "client_allowed_scopes"
    __table_args__ = (
        # disabled due to SQLAlchemy's current limitation
        # sa.UniqueConstraint("client_id", "scope"),
    )

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(
        sa.Integer(),
        sa.ForeignKey(UserPool.id),
        nullable=False,
        default=pool_id_default,
    )
    client_id = sa.Column(sa.Integer(), sa.ForeignKey(Client.id))
    scope = sa.Column(sa.String(255), nullable=False)

    client = sa.orm.relationship(Client)


users_groups = sa.Table(
    "users_groups",
    Base.metadata,
    sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id")),
    sa.Column("group_id", sa.Integer(), sa.ForeignKey("groups.id")),
    sa.UniqueConstraint("user_id", "group_id"),
)


class Group(Base, CreatedUpdatedMixin):
    __tablename__ = "groups"

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(sa.Integer(), sa.ForeignKey("userpools.id"), nullable=False)
    key = sa.Column(sa.String(255), nullable=False, default=lambda: generate_key(9))
    name = sa.Column(sa.String(255))

    users = sa.orm.relationship("User", back_populates="groups", secondary=users_groups)
    pool = sa.orm.relationship(UserPool, back_populates="groups")


class User(Base, CreatedUpdatedMixin):
    __tablename__ = "users"

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(sa.Integer(), sa.ForeignKey("userpools.id"), nullable=False)
    key = sa.Column(sa.String(255), nullable=False, unique=True)
    name = sa.Column(sa.String(255), nullable=False)
    given_name = sa.Column(sa.String(255), nullable=True)
    family_name = sa.Column(sa.String(255), nullable=True)
    middle_name = sa.Column(sa.String(255), nullable=True)
    nickname = sa.Column(sa.String(255), nullable=True)
    preferred_username = sa.Column(sa.String(255), nullable=True)
    profile = sa.Column(sa.String(255), nullable=True)
    picture = sa.Column(sa.String(255), nullable=True)
    website = sa.Column(sa.String(255), nullable=True)
    email = sa.Column(sa.String(255), nullable=False)
    email_verified = sa.Column(sa.Boolean(), nullable=False, default=False)
    gender = sa.Column(sa.String(255), nullable=True)
    birthdate = sa.Column(sa.Date(), nullable=True)
    zoneinfo = sa.Column(sa.String(255), nullable=True)
    locale = sa.Column(sa.String(255), nullable=True)
    phone_number = sa.Column(sa.String(255), nullable=True)
    phone_number_verified = sa.Column(sa.Boolean(), nullable=True)
    address = sa.Column(sa.String(255), nullable=True)
    cognito_mfa_enabled = sa.Column(sa.Boolean(), nullable=False, default=True)
    password = sa.Column(sa.String(255), nullable=False)

    pool = sa.orm.relationship(UserPool, back_populates="users")
    groups = sa.orm.relationship(
        Group, back_populates="users", secondary=users_groups, uselist=True
    )  # uselist=True is necessary to cope with invalid inference by sqlalchemy-stub

    __table_args__ = (
        sa.Index(
            "ix_users_pool_id_email", pool_id, sql_func.func.lower(email), unique=True
        ),
        sa.UniqueConstraint(pool_id, phone_number),
        sa.UniqueConstraint(pool_id, name),
        sa.UniqueConstraint(pool_id, preferred_username),
    )

    def __str__(self):
        return f"{self.name} ({self.key})"


class Token(Base):
    __tablename__ = "tokens"

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(sa.Integer(), sa.ForeignKey("userpools.id"), nullable=False)
    client_id = sa.Column(sa.Integer(), sa.ForeignKey(Client.id), nullable=False)
    user_id = sa.Column(sa.Integer(), sa.ForeignKey(User.id), nullable=False)
    scope = sa.Column(sa.String(255), nullable=False)
    access_token = sa.Column(sa.String(2048), nullable=False)
    refresh_token = sa.Column(sa.String(2048), nullable=True)
    expires_at = sa.Column(sa.DateTime(), nullable=False)
    event_id = sa.Column(sa.Integer(), sa.ForeignKey("events.id"), nullable=False)

    client = sa.orm.relationship(Client)
    pool = sa.orm.relationship(UserPool)
    user = sa.orm.relationship(User)
    event = sa.orm.relationship("Event")


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(sa.Integer(), sa.ForeignKey("userpools.id"), nullable=False)
    client_id = sa.Column(sa.Integer(), sa.ForeignKey(Client.id), nullable=False)
    user_id = sa.Column(sa.Integer(), sa.ForeignKey(User.id), nullable=False)
    scope = sa.Column(sa.String(255), nullable=False)
    code = sa.Column(sa.String(255), nullable=False)
    redirect_uri = sa.Column(sa.String(255), nullable=False)
    nonce = sa.Column(sa.String(255), nullable=True)
    code_challenge = sa.Column(sa.String(255), nullable=True)
    code_challenge_method = sa.Column(sa.String(255), nullable=True)
    event_id = sa.Column(sa.Integer(), sa.ForeignKey("events.id"), nullable=False)

    client = sa.orm.relationship(Client)
    pool = sa.orm.relationship(UserPool)
    user = sa.orm.relationship(User)
    event = sa.orm.relationship("Event")

    __table_args__ = (
        sa.Index("ix_authorization_codes_client_id_code", client_id, code),
    )


class Event(Base, CreatedMixin):
    __tablename__ = "events"

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(sa.Integer(), sa.ForeignKey("userpools.id"), nullable=False)
    key = sa.Column(sa.String(255), nullable=False)
    type = sa.Column(sa.String(255), nullable=True)

    pool = sa.orm.relationship(UserPool)
