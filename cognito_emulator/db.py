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

import contextvars

import sqlalchemy as sa  # type: ignore
from sqlalchemy.ext.declarative import declarative_base  # type: ignore
from starlette.types import ASGIApp, Receive, Scope, Send

metadata = sa.MetaData()
Base = declarative_base(metadata=metadata)


registry: contextvars.ContextVar = contextvars.ContextVar(__name__)


class ContextLocalRegistry(sa.util.ScopedRegistry):
    def __init__(self, registry):
        self.registry = registry

    def __call__(self):
        return self.registry.get()

    def has(self):
        return self.registry.get(None) is not None

    def set(self, obj):
        pass

    def clear(self):
        pass


class OurScopedSession(sa.orm.scoped_session):
    def __init__(self, session_factory):
        self.session_factory = session_factory
        self.registry = ContextLocalRegistry(registry)


session_factory = sa.orm.sessionmaker()
session = OurScopedSession(session_factory)


class SQLAlchemyMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        registry.set(session_factory())
        try:
            return await self.app(scope, receive, send)
        finally:
            session.remove()
            registry.set(None)
