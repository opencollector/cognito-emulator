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

import sqlalchemy as sa  # type: ignore
from sqlalchemy import orm
from sqlalchemy.ext.hybrid import hybrid_property

from ..db import Base
from ..models import CreatedUpdatedMixin


class IdentityPool(Base, CreatedUpdatedMixin):
    __tablename__ = "identitypools"

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    name = sa.Column(sa.String(255), nullable=False, unique=True)
    key = sa.Column(sa.String(255), nullable=False)
    allow_unauthenticated_identities = sa.Column(sa.Boolean(), nullable=False)

    __table_args__ = (sa.Index("ix_pools_key", key),)


class Identity(Base, CreatedUpdatedMixin):
    __tablename__ = "identities"

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(sa.Integer(), sa.ForeignKey(IdentityPool.id), nullable=False)
    key = sa.Column(sa.String(255), nullable=False)

    pool = orm.relationship(IdentityPool)
    logins = orm.relationship("Login", uselist=True)


class Provider(Base, CreatedUpdatedMixin):
    __tablename__ = "providers"

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(sa.Integer(), sa.ForeignKey(IdentityPool.id), nullable=False)
    name = sa.Column(sa.String(255), nullable=False)
    client_id = sa.Column(sa.String(255), nullable=False)
    server_side_token_check = sa.Column(sa.Boolean(), nullable=False)

    @hybrid_property
    def url_safe_name(self):
        return self.name.replace("/", "--")

    @url_safe_name.expression  # type: ignore
    def url_safe_name(cls):
        return sa.sql.func.replace(cls.name, "/", "--")

    pool = orm.relationship(IdentityPool)


class Login(Base, CreatedUpdatedMixin):
    __tablename__ = "logins"

    id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
    pool_id = sa.Column(sa.Integer(), sa.ForeignKey(IdentityPool.id), nullable=False)
    identity_id = sa.Column(sa.Integer(), sa.ForeignKey(Identity.id), nullable=False)
    provider_id = sa.Column(sa.Integer(), sa.ForeignKey(Provider.id), nullable=False)
    subject = sa.Column(sa.String(255), nullable=False)

    pool = orm.relationship(IdentityPool)
    identity = orm.relationship(Identity, back_populates="logins")
    provider = orm.relationship(Provider)
