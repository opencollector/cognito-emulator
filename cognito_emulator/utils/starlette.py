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

import functools
import inspect
import typing

from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    UnauthenticatedUser,
)
from starlette.exceptions import HTTPException
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from ..executor import as_coroutine_function

ContextualHandler = typing.Callable[[], typing.Awaitable[Response]]


class ContextualHTTPEndpoint:
    @classmethod
    def request_factory(cls, scope: Scope, receive: Receive) -> Request:
        return Request(scope, receive)

    def __init__(self, scope: Scope, receive: Receive, send: Send):
        assert scope["type"] == "http"
        self.scope = scope
        self.receive = receive
        self.send = send
        request = self.request_factory(self.scope, self.receive)  # type: ignore
        self.request = request

    def __await__(self) -> typing.Generator:
        return self.dispatch().__await__()

    def get_handler(self) -> typing.Optional[ContextualHandler]:
        handler_name = (
            "get" if self.request.method == "HEAD" else self.request.method.lower()
        )
        handler = getattr(self, handler_name, None)
        if handler is None:
            return None
        return as_coroutine_function(handler)

    async def post_get_handler_hook(
        self, handler: ContextualHandler
    ) -> ContextualHandler:
        return handler

    async def dispatch(self):
        handler = self.get_handler()
        if handler is None:
            response = await self.method_not_allowed()
        else:
            handler = await self.post_get_handler_hook(handler)
            response = await handler()
        await response(self.scope, self.receive, self.send)

    async def method_not_allowed(self) -> Response:
        if "app" in self.scope:
            raise HTTPException(status_code=405)
        return PlainTextResponse("Method Not Allowed", status_code=405)


def authenticate_by(
    backend: AuthenticationBackend,
) -> typing.Callable[
    [typing.Union[ASGIApp, typing.Callable[[Request], typing.Awaitable[Response]]]],
    typing.Union[ASGIApp, typing.Callable[[Request], typing.Awaitable[Response]]],
]:
    def _(fn):
        if inspect.isfunction(fn) or inspect.ismethod(fn):

            @functools.wrap(fn)
            async def _(request: Request):
                pair = await backend.authenticate(request)
                if pair is None:
                    pair = AuthCredentials(), UnauthenticatedUser()
                request.scope["auth"], request.scope["user"] = pair

            return _
        else:
            return AuthenticationMiddleware(fn, backend)

    return _
