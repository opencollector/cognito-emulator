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

import sqlalchemy as sa  # type: ignore
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.routing import BaseRoute, Mount
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from .. import executor
from ..db import SQLAlchemyMiddleware, session_factory
from ..middlewares import RequestTimeMiddleware, TemplateShortcutMiddleware

logger = logging.getLogger(__name__)
basedir = pathlib.Path(__file__).parent


def create_application(
    database_url: str,
    user_pool_emulator_url_base: str,
    debug: bool = False,
    max_pool_workers: int = 10,
    region: str = "mars-east-1",
    prepended_routes: typing.Iterable[BaseRoute] = [],
):
    from .views import admin as admin_views
    from .views import index as index_views

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
        Mount("/", index_views.routes),
    ]

    app = Starlette(
        debug=debug,
        routes=routes,
        middleware=[
            Middleware(RequestTimeMiddleware),
            Middleware(SQLAlchemyMiddleware),
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
    app.state.user_pool_emulator_url_base = user_pool_emulator_url_base
    app.state.region = region
    app.state.templates = Jinja2Templates(directory=str(basedir / "templates"))
    app.state.uuidgen = lambda: str(uuid.uuid4())
    return app
