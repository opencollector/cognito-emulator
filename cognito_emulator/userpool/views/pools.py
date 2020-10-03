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
import typing
from urllib.parse import urlparse

from sqlalchemy.orm import exc as orm_exc
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Router
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND

from ...executor import async_
from ...middlewares import WithTemplates
from ...utils import ContextualHTTPEndpoint
from ..application import POOL_KEY
from ..models import AuxiliaryIdentityAttribute, UserPool
from ..utils import build_jwt_public_key_from_private_key

logger = logging.getLogger(__name__)
routes = Router()


class PoolHTTPEndpoint(ContextualHTTPEndpoint):
    @property
    def templates(self):
        return lambda name, context={}, *args, **kwargs: (
            typing.cast(WithTemplates, self.request).templates(
                name,
                {**context, "pool": self.request.scope.get(POOL_KEY)},
                *args,
                **kwargs,
            )
        )

    @property
    def pool(self) -> typing.Optional[UserPool]:
        return typing.cast(typing.Optional[UserPool], self.request.get(POOL_KEY))

    @property
    def per_pool_session(self) -> typing.Dict[str, typing.Any]:
        pool = self.pool
        if pool is not None:
            return self.request.scope["session"].setdefault(pool.key, {})
        else:
            return self.request.scope["session"]

    async def dispatch(self):
        if self.request.get(POOL_KEY) is None:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND)
        await super().dispatch()

    @property
    def success_page_url(self):
        return self.request.url_for("pools:signin_success", pool=self.pool.key)


def bool_val(v: typing.Optional[str]) -> bool:
    return v not in ("false", "no", "0", None)


@routes.route("/signin", name="signin")
class SigninEndpoint(PoolHTTPEndpoint):
    template = "pools/signin.html"

    @property
    def back_to(self) -> typing.Optional[str]:
        return self.request.session.get("back_to")

    @back_to.setter
    def back_to(self, value: typing.Optional[str]):
        self.request.session["back_to"] = value

    def render_template(self, context: typing.Dict[str, typing.Any] = {}) -> Response:
        assert self.pool is not None
        if self.pool.username_attributes:
            email = AuxiliaryIdentityAttribute.EMAIL in self.pool.username_attributes
            phone_number = (
                AuxiliaryIdentityAttribute.PHONE_NUMBER in self.pool.username_attributes
            )
            if email and phone_number:
                label = "E-mail address or phone number"
            elif email:
                label = "E-mail address"
            elif phone_number:
                label = "Phone number"
            else:
                raise AssertionError()
        else:
            label = "User name"
        context["username_label"] = label
        return self.templates(self.template, context=context)

    async def get(self):
        assert self.pool is not None
        back_to = self.request.query_params.get("back_to")
        reauth = bool_val(self.request.query_params.get("reauth"))
        if self.request.user.is_authenticated and not reauth:
            return RedirectResponse(back_to or self.success_page_url)
        parsed_back_to = urlparse(back_to)
        if (
            parsed_back_to.scheme and parsed_back_to.scheme != self.request.url.scheme
        ) or (
            parsed_back_to.hostname
            and parsed_back_to.hostname != self.request.url.hostname
        ):
            raise HTTPException(status_code=HTTP_400_BAD_REQUEST)
        if back_to is not None:
            self.back_to = back_to
        return self.render_template(context={"form": {"reauth": reauth}})

    async def post(self):
        assert self.pool is not None
        form = await self.request.form()
        try:
            user = await async_(lambda: self.pool.query_user(form["username"]).one())()
            self.request.app.state.kdf.verify(user.password, form["password"])
        except Exception as e:
            logger.debug(f"failed login attempt: {form['username']} - {e!r}")
            return self.render_template(
                context={
                    "form": form,
                    "alerts": ["No user registered with that user name and password."],
                }
            )
        self.per_pool_session["user_id"] = user.id
        return RedirectResponse(self.back_to or self.success_page_url, status_code=302)


@routes.route("/signin/success", name="signin_success")
class SignedinEndpoint(PoolHTTPEndpoint):
    template = "pools/signin_success.html"

    async def get(self):
        return self.templates(self.template)


@routes.route("/signout", name="signout", methods=["post"])
class SignOutEndpoint(PoolHTTPEndpoint):
    async def post(self):
        form = await self.request.form()
        client_id = form.get("client_id")
        try:
            client = await async_(
                self.pool.clients.filter_by(oauth2_client_id=client_id).one
            )()
        except orm_exc.NoResultFound as e:
            raise HTTPException(status_code=HTTP_404_NOT_FOUND) from e
        back_to = form.get("back_to")
        if back_to is None or back_to not in client.logout_uris:
            back_to = self.request.url_for("pools:signout_success", pool=self.pool.key)
        if self.request.user.is_authenticated:
            del self.per_pool_session["user_id"]
        return RedirectResponse(back_to, status_code=302)


@routes.route("/signout/success", name="signout_success")
class SignedOutEndpoint(PoolHTTPEndpoint):
    async def get(self):
        return self.templates("pools/signout_success.html")


@routes.route("/", name="index")
class IndexEndpoint(PoolHTTPEndpoint):
    async def get(self):
        return self.templates("pools/index.html")


@routes.route("/.well-known/jwks.json", name="signin_success")
class JWKSEndpoint(PoolHTTPEndpoint):
    async def get(self):
        keys = []
        if isinstance(self.request.app.state.jwt_config.key, dict):
            public_jwk = build_jwt_public_key_from_private_key(
                self.request.app.state.jwt_config.key
            )
            public_jwk["use"] = "sig"
            keys.append(public_jwk)
        return JSONResponse(
            {
                "keys": keys,
            }
        )
