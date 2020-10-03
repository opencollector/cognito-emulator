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

import typing

from starlette.background import BackgroundTask
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from .utils import utcnow

NOW_KEY = __name__ + ".now"

TemplateRenderer = typing.Callable[..., Response]


class WithTemplates(typing.Protocol):
    templates: TemplateRenderer


class RequestTimeMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        scope[NOW_KEY] = utcnow()
        await self.app(scope, receive, send)


class TemplateShortcutMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        # currently unsupported in mypy
        typing.cast(typing.Type[WithTemplates], Request).templates = property(
            lambda self: self.scope["templates"]
        )  # type: ignore

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        def _(
            template: typing.Any,
            context: dict = None,
            status_code: int = 200,
            headers: dict = None,
            media_type: str = None,
            background: BackgroundTask = None,
        ) -> Response:
            if context is None:
                context = {}
            context["request"] = request
            return request.app.state.templates.TemplateResponse(
                template,
                context=context,
                status_code=status_code,
                headers=headers,
                media_type=media_type,
                background=background,
            )

        request.scope["templates"] = _  # type: ignore
        return await call_next(request)


class apply_middlewares:
    def __init__(self, app: ASGIApp, middleware: typing.Sequence[Middleware]):
        self.orig_app = app
        for cls, options in reversed(middleware):
            app = cls(app, **options)
        self.app = app
        self.middleware = middleware

    def __getattr__(self, k):
        return getattr(self.orig_app, k)

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        await self.app(scope, receive, send)
