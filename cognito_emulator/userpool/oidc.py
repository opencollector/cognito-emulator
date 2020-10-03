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

import copy
import dataclasses
import logging
import typing
import uuid
from datetime import datetime, timedelta, timezone

from authlib.common.urls import add_params_to_uri  # type: ignore
from authlib.jose.errors import ExpiredTokenError  # type: ignore
from authlib.jose.rfc7519.jwt import JsonWebToken  # type: ignore
from authlib.oauth2.rfc6749 import (  # type: ignore
    AuthorizationServer as _AuthorizationServer,
)
from authlib.oauth2.rfc6749 import ClientAuthentication, ClientMixin  # type: ignore
from authlib.oauth2.rfc6749 import HttpRequest as _HttpRequest  # type: ignore
from authlib.oauth2.rfc6749 import (  # type: ignore
    InvalidClientError,
    InvalidGrantError,
    MissingAuthorizationError,
    OAuth2Error,
)
from authlib.oauth2.rfc6749 import OAuth2Request as _OAuth2Request  # type: ignore
from authlib.oauth2.rfc6749 import TokenMixin, UnsupportedTokenTypeError  # type: ignore
from authlib.oauth2.rfc6749.grants import (  # type: ignore
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import BaseGrant
from authlib.oauth2.rfc6750 import BearerToken as _BearerToken  # type: ignore
from authlib.oauth2.rfc6750 import (
    BearerTokenValidator as _BearerTokenValidator,  # type: ignore
)
from authlib.oauth2.rfc6750 import (  # type: ignore
    InvalidRequestError,
    InvalidTokenError,
)
from authlib.oauth2.rfc7636 import CodeChallenge  # type: ignore
from authlib.oidc.core import AuthorizationCodeMixin  # type: ignore
from authlib.oidc.core import UserInfo  # type: ignore
from authlib.oidc.core import OpenIDCode as _OpenIDCode  # type: ignore
from authlib.oidc.core import (  # type: ignore
    OpenIDImplicitGrant as _OpenIDImplicitGrant,
)
from authlib.oidc.core.grants.util import _generate_id_token_payload, _jwt_encode, is_openid_scope  # type: ignore
from sqlalchemy.orm import exc as orm_exc  # type: ignore
from starlette.authentication import AuthCredentials, AuthenticationBackend, BaseUser
from starlette.datastructures import URL, Headers
from starlette.requests import HTTPConnection, Request
from starlette.responses import (
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.status import HTTP_400_BAD_REQUEST

from ..auth import StarletteUserWrapper
from ..db import session
from ..executor import async_, await_
from ..utils import utcnow
from .models import AuthorizationCode, Client, Event, Token, User

Scalar = typing.Union[str, int, float, bool]
TokenDict = typing.MutableMapping[str, Scalar]
JSONValue = typing.Union[
    str, int, float, bool, typing.Sequence[typing.Any], typing.Mapping[str, typing.Any]
]

logger = logging.getLogger(__name__)


EVENT_KEY = __name__ + ".event"


class UserModelWrapper:
    def __init__(self, obj: User):
        self.obj = obj


class OAuth2Request(_OAuth2Request):
    _orig_request: Request
    client: typing.Optional["ClientModelWrapper"]
    user: typing.Optional[UserModelWrapper]

    def __init__(self, request: Request):
        super().__init__(
            request.method,
            str(request.url),
            await_(request.form()),
            request.headers,
        )
        self._orig_request = request
        self.client = None
        self.user = None

    @property
    def event(self) -> Event:
        return typing.cast(Event, self._orig_request.scope[EVENT_KEY])


TOAuth2Request = typing.TypeVar("TOAuth2Request", bound=_OAuth2Request)


def clone_oauth2_request(oauth2_request: TOAuth2Request) -> TOAuth2Request:
    new_request = object.__new__(oauth2_request.__class__)
    for k in dir(oauth2_request):
        if not hasattr(oauth2_request.__class__, k):
            setattr(new_request, k, copy.copy(getattr(oauth2_request, k)))
    return new_request


class HttpRequest(_HttpRequest):
    _orig_request: HTTPConnection

    def __init__(self, request: HTTPConnection):
        super().__init__(
            request.scope["method"],
            str(URL(scope=request.scope)),
            None,
            Headers(scope=request.scope),
        )
        self._orig_request = request


class ClientModelWrapper(ClientMixin):
    obj: Client

    def __init__(self, obj):
        self.obj = obj

    def get_client_id(self) -> str:
        return self.obj.oauth2_client_id

    def get_default_redirect_uri(self):
        return self.obj.default_redirect_uri

    def get_allowed_scope(self, scope: typing.Union[str, typing.Iterable]) -> str:
        scopes: typing.Set[str]
        if isinstance(scope, str):
            scopes = set(scope.split(None) if scope != "" else [])
        else:
            scopes = set(scope)
        return " ".join(set(self.obj.scopes) & scopes)

    def get_scope(self) -> str:
        return " ".join(self.obj.scopes)

    def check_redirect_uri(self, redirect_uri) -> bool:
        return redirect_uri in self.obj.redirect_uris

    def has_client_secret(self) -> bool:
        return bool(self.obj.oauth2_client_secret)

    def check_client_secret(self, client_secret: str) -> bool:
        return (
            self.obj.oauth2_client_secret != ""
            and self.obj.oauth2_client_secret == client_secret
        )

    def check_token_endpoint_auth_method(self, method: str) -> bool:
        return method != "none" or not self.has_client_secret()

    def check_response_type(self, response_type: str) -> bool:
        return response_type in ["code", "token"]

    def check_grant_type(self, grant_type: str) -> bool:
        return grant_type in ["authorization_code", "implicit"]


def get_client_by_id(client_id: str) -> typing.Optional[ClientModelWrapper]:
    logger.debug(f"get_client_by_id: client_id={client_id}")
    try:
        client = session.query(Client).filter_by(oauth2_client_id=client_id).one()
        return ClientModelWrapper(client)
    except orm_exc.NoResultFound:
        logger.debug("client not found")
        return None


def get_client_at_authorization_endpoint(
    request: Request,
) -> typing.Optional[ClientModelWrapper]:
    return get_client_by_id(OAuth2Request(request).client_id)


def get_client_at_token_endpoint(
    request: Request,
) -> typing.Optional[ClientModelWrapper]:
    try:
        return ClientAuthentication(get_client_by_id).authenticate(
            OAuth2Request(request),
            ["client_secret_basic", "client_secret_post", "none"],
        )
    except InvalidClientError:
        return None


ExpiresGenerator = typing.Callable[[OAuth2Request, ClientModelWrapper, str], int]
TokenGenerator = typing.Callable[
    [
        OAuth2Request,
        ClientModelWrapper,
        str,
        Event,
        int,
        typing.Optional[UserModelWrapper],
        typing.Optional[str],
    ],
    str,
]


class BearerToken(_BearerToken):
    def __init__(
        self,
        access_token_generator: TokenGenerator,
        refresh_token_generator: typing.Optional[TokenGenerator] = None,
        expires_generator: typing.Optional[ExpiresGenerator] = None,
    ):
        super().__init__(
            access_token_generator=access_token_generator,
            refresh_token_generator=refresh_token_generator,
            expires_generator=expires_generator,
        )

    def _get_expires_in(
        self, request: OAuth2Request, client: ClientModelWrapper, grant_type: str
    ) -> int:
        if self.expires_generator is None:
            expires_in = self.GRANT_TYPES_EXPIRES_IN.get(
                grant_type, self.DEFAULT_EXPIRES_IN
            )
        elif callable(self.expires_generator):
            expires_in = self.expires_generator(request, client, grant_type)
        elif isinstance(self.expires_generator, (int, float)):
            expires_in = self.expires_generator
        else:
            expires_in = self.DEFAULT_EXPIRES_IN
        return expires_in

    def __call__(
        self,
        request: OAuth2Request,
        client: ClientModelWrapper,
        grant_type: str,
        event: Event,
        user: typing.Optional[UserModelWrapper] = None,
        scope: typing.Optional[str] = None,
        expires_in: typing.Optional[int] = None,
        include_refresh_token: bool = True,
    ):
        if expires_in is None:
            expires_in = self._get_expires_in(request, client, grant_type)
        access_token = self.access_token_generator(
            request, client, grant_type, event, expires_in, user, scope
        )

        token = {
            "token_type": "Bearer",
            "access_token": access_token,
            "expires_in": expires_in,
        }
        if include_refresh_token and self.refresh_token_generator:
            token["refresh_token"] = self.refresh_token_generator(
                request, client, grant_type, event, expires_in, user, scope
            )
        if scope:
            token["scope"] = scope
        return token


class AuthorizationCodeModelWrapper(AuthorizationCodeMixin):
    def __init__(self, obj: AuthorizationCode):
        self.obj = obj

    def get_redirect_uri(self) -> str:
        return self.obj.redirect_uri

    def get_scope(self) -> str:
        return self.obj.scope

    def get_nonce(self) -> typing.Optional[str]:
        return self.obj.nonce

    def get_auth_time(self) -> int:
        return self.obj.event.created_at.timestamp()

    @property
    def code_challenge(self) -> typing.Optional[str]:
        return self.obj.code_challenge

    @property
    def code_challenge_method(self) -> typing.Optional[str]:
        return self.obj.code_challenge_method


class DummyCredential(AuthorizationCodeMixin):
    auth_time: datetime

    def __init__(self, auth_time: datetime):
        self.auth_time = auth_time

    def get_nonce(self) -> typing.Optional[str]:
        return None

    def get_auth_time(self) -> float:
        return self.auth_time.timestamp()


class OpenIDCodeMixin:
    def exists_nonce(self, nonce: str, request: OAuth2Request):
        assert request.client is not None
        return (
            session.query(AuthorizationCode)
            .filter_by(client=request.client.obj, nonce=nonce)
            .exists()
        )

    def _get_jwt_config(
        self, grant: BaseGrant
    ) -> typing.Dict[
        str,
        typing.Union[
            typing.Union[Scalar, bytes],
            typing.Sequence[typing.Union[Scalar, bytes]],
            typing.Dict[str, typing.Union[Scalar, bytes]],
        ],
    ]:
        jwt_config = grant.server.jwt_config
        return {
            "key": jwt_config.key,
            "alg": jwt_config.signature_algorithm,
            "iss": jwt_config.issuer,
            "exp": jwt_config.ttl.total_seconds(),
        }

    def generate_user_info(self, user: UserModelWrapper, scope: str) -> UserInfo:
        scopes = scope.split()
        obj = user.obj
        info = UserInfo(
            sub=obj.key,
            updated_at=obj.updated_at.replace(tzinfo=timezone.utc).isoformat(),
        )
        if "email" in scopes:
            info.update(
                email=obj.email,
                email_verified=obj.email_verified,
            )
        if "profile" in scopes:
            info.update(
                name=obj.name,
                given_name=obj.given_name,
                family_name=obj.family_name,
                middle_name=obj.middle_name,
                nickname=obj.nickname,
                preferred_username=obj.preferred_username,
                profile=obj.profile,
                picture=obj.picture,
                website=obj.website,
                gender=obj.gender,
                birthdate=obj.birthdate,
                zoneinfo=obj.zoneinfo,
                locale=obj.locale,
                phone_number=obj.phone_number,
                phone_number_verified=obj.phone_number_verified,
                address=obj.address,
            )
        info["cognito:username"] = obj.key
        info["cognito:groups"] = ([g.name for g in obj.groups],)
        info["cognito:mfa_enabled"] = False
        return info

    def _generate_id_token(
        self,
        token: TokenDict,
        user_info: typing.Dict[str, typing.Any],
        key: typing.Dict[str, typing.Union[Scalar, bytes]],
        alg: str,
        iss: str,
        aud: typing.Sequence[str],
        exp: typing.Union[float, int],
        nonce: typing.Optional[str] = None,
        auth_time: typing.Optional[int] = None,
        code: typing.Optional[str] = None,
        **extras: typing.Any,
    ):
        payload = _generate_id_token_payload(
            alg=alg,
            iss=iss,
            aud=aud,
            exp=exp,
            nonce=nonce,
            auth_time=auth_time,
            code=code,
            access_token=token.get("access_token"),
        )
        payload.update(user_info)
        payload.update(extras)
        return _jwt_encode(alg, payload, key)


class OpenIDCode(_OpenIDCode, OpenIDCodeMixin):
    def exists_nonce(self, nonce: str, request: OAuth2Request):
        return OpenIDCodeMixin.exists_nonce(self, nonce, request)

    def get_jwt_config(
        self, grant
    ) -> typing.Dict[
        str,
        typing.Union[
            typing.Union[Scalar, bytes],
            typing.Sequence[typing.Union[Scalar, bytes]],
            typing.Dict[str, typing.Union[Scalar, bytes]],
        ],
    ]:
        return OpenIDCodeMixin._get_jwt_config(self, grant)

    def generate_user_info(self, user: UserModelWrapper, scope: str) -> UserInfo:
        return OpenIDCodeMixin.generate_user_info(self, user, scope)

    def process_token(
        self, grant: "AuthorizationCodeGrant", token: TokenDict
    ) -> TokenDict:
        scope = token.get("scope")
        if not scope or not is_openid_scope(scope):
            return token

        request = grant.request
        credential = request.credential

        config = self.get_jwt_config(grant)

        assert request.user is not None
        assert isinstance(scope, str)
        user_info = self.generate_user_info(request.user, scope)
        key = config.pop("key")
        assert isinstance(key, dict)
        alg = config.pop("alg")
        assert isinstance(alg, str)
        iss = config.pop("iss")
        assert isinstance(iss, str)
        exp = config.pop("exp")
        assert isinstance(exp, (float, int))
        code = config.pop("code", None)
        assert code is None or isinstance(code, str)
        id_token = self._generate_id_token(
            token,
            user_info,
            key=key,
            alg=alg,
            iss=iss,
            aud=self.get_audiences(request),
            exp=exp,
            nonce=credential.get_nonce(),
            auth_time=credential.get_auth_time(),
            code=code,
            token_use="id",
            **config,
        )
        token["id_token"] = id_token
        return token


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    request: OAuth2Request
    server: "AuthorizationServer"
    event: typing.Optional[Event] = None

    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code: str, request: OAuth2Request):
        assert request.client is not None
        assert request.user is not None
        code_challenge = request.args.get("code_challenge")
        code_challenge_method = request.args.get("code_challenge_method")
        authz_code = AuthorizationCode(
            pool_id=request.client.obj.pool_id,
            client=request.client.obj,
            user=request.user.obj,
            event=request.event,
            scope=request.client.get_allowed_scope(request.scope or []),
            code=code,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            redirect_uri=(
                request.redirect_uri or request.client.get_default_redirect_uri()
            ),
        )
        session.add(authz_code)
        session.commit()

    def query_authorization_code(
        self, code: str, client: ClientModelWrapper
    ) -> typing.Optional[AuthorizationCodeModelWrapper]:
        try:
            authz_code = (
                session.query(AuthorizationCode)
                .filter_by(client=client.obj, code=code)
                .one()
            )
            self.event = authz_code.event
            return AuthorizationCodeModelWrapper(authz_code)
        except orm_exc.NoResultFound:
            return None

    def authenticate_user(
        self, authz_code: AuthorizationCodeModelWrapper
    ) -> typing.Optional[UserModelWrapper]:
        return (
            UserModelWrapper(authz_code.obj.user)
            if authz_code.obj.user is not None
            else None
        )

    def delete_authorization_code(self, authz_code: AuthorizationCodeModelWrapper):
        session.delete(authz_code.obj)
        session.commit()

    def generate_token(
        self,
        client: ClientModelWrapper,
        grant_type: str,
        user: typing.Optional[UserModelWrapper] = None,
        scope: typing.Optional[str] = None,
        expires_in: typing.Optional[typing.Union[int, float]] = None,
        include_refresh_token: bool = True,
    ):
        assert self.event is not None
        return self.server.generate_token(
            request=self.request,
            client=client,
            grant_type=grant_type,
            event=self.event,
            user=user,
            scope=scope,
            expires_in=expires_in,
            include_refresh_token=include_refresh_token,
        )

    def create_token_response(self):
        client = self.request.client
        authorization_code = self.request.credential

        user = self.authenticate_user(authorization_code)
        if not user:
            raise InvalidRequestError('There is no "user" for this code.')

        scope = authorization_code.get_scope()
        token = self.generate_token(
            client=client,
            grant_type="authorization_code",
            user=user,
            scope=scope,
            include_refresh_token=client.check_grant_type("refresh_token"),
        )
        logger.debug("Issue token %r to %r", token, client)

        self.request.user = user
        self.save_token(token)
        self.execute_hook("process_token", token=token)
        self.delete_authorization_code(authorization_code)
        return 200, token, self.TOKEN_RESPONSE_HEADER


class OpenIDImplicitGrant(_OpenIDImplicitGrant, OpenIDCodeMixin):
    def get_jwt_config(
        self,
    ) -> typing.Dict[
        str,
        typing.Union[
            typing.Union[Scalar, bytes],
            typing.Sequence[typing.Union[Scalar, bytes]],
            typing.Dict[str, typing.Union[Scalar, bytes]],
        ],
    ]:
        return OpenIDCodeMixin._get_jwt_config(self, self)

    def process_implicit_token(self, token, code=None):
        config = self.get_jwt_config()
        key = config.pop("key")
        assert isinstance(key, dict)
        alg = config.pop("alg")
        assert isinstance(alg, str)
        iss = config.pop("iss")
        assert isinstance(iss, str)
        exp = config.pop("exp")
        assert isinstance(exp, (float, int))

        user_info = self.generate_user_info(self.request.user, token["scope"])
        id_token = self._generate_id_token(
            token,
            user_info,
            key=key,
            alg=alg,
            iss=iss,
            aud=self.get_audiences(self.request),
            exp=exp,
            nonce=self.request.data.get("nonce"),
            code=code,
            token_use="id",
            **config,
        )
        token["id_token"] = id_token
        return token

    def generate_token(
        self,
        client: ClientModelWrapper,
        grant_type: str,
        user: typing.Optional[UserModelWrapper] = None,
        scope: typing.Optional[str] = None,
        expires_in: typing.Optional[typing.Union[int, float]] = None,
        include_refresh_token: bool = True,
    ) -> TokenDict:
        return self.server.generate_token(
            request=self.request,
            client=client,
            grant_type=grant_type,
            event=self.event,
            user=user,
            scope=scope,
            expires_in=expires_in,
            include_refresh_token=include_refresh_token,
        )


JWKRepr = typing.Dict[str, str]


@dataclasses.dataclass
class JWTConfiguration:
    key: typing.Union[bytes, JWKRepr]
    public_key: typing.Union[bytes, JWKRepr]
    signature_algorithm: str
    signature_params: typing.Dict[str, str]
    encryption_algorithm: str
    encryption_params: typing.Dict[str, str]
    issuer: str
    ttl: timedelta


TokenGeneratorFacade = typing.Callable[
    [
        OAuth2Request,
        ClientMixin,
        str,
        Event,
        typing.Optional[ClientModelWrapper],
        typing.Optional[str],
        typing.Optional[int],
        bool,
    ],
    TokenDict,
]


class AuthorizationServer(_AuthorizationServer):
    now: typing.Callable[[], datetime]
    uuidgen: typing.Callable[[], str]

    def __init__(
        self,
        query_client: typing.Callable[[str], ClientMixin],
        save_token: typing.Callable[[TokenDict, _OAuth2Request], None],
        now: typing.Callable[[], datetime],
        uuidgen: typing.Callable[[], str],
        generate_token: typing.Optional[TokenGeneratorFacade] = None,
        metadata: typing.Optional[TokenDict] = None,
        jwt_config: typing.Optional[JWTConfiguration] = None,
    ):
        self.jwt_config = jwt_config
        # see: https://github.com/python/mypy/issues/2427
        self.now = now  # type: ignore
        self.uuidgen = uuidgen  # type: ignore
        super().__init__(query_client, save_token, generate_token, metadata)

    def create_oauth2_request(self, request: Request) -> _OAuth2Request:
        return OAuth2Request(request)

    def create_json_request(self, request: Request) -> _HttpRequest:
        return HttpRequest(request)

    def handle_response(
        self,
        status: int,
        body: JSONValue,
        headers: typing.Sequence[typing.Tuple[str, str]],
    ) -> Response:
        return JSONResponse(body, status_code=status, headers=dict(headers))

    def get_redirect_uri_if_available(self, request: _OAuth2Request) -> str:
        _request = clone_oauth2_request(request)
        _request.data["response_type"] = "code"
        grant = AuthorizationCodeGrant(_request, self)
        return grant.validate_authorization_request()

    def create_authorization_response(
        self, request: Request, grant_user: typing.Optional[UserModelWrapper]
    ) -> Response:
        error = "server_error"
        oauth2_request = self.create_oauth2_request(request)

        redirect_uri: typing.Optional[str]

        try:
            redirect_uri = self.get_redirect_uri_if_available(oauth2_request)
        except OAuth2Error as e:
            return PlainTextResponse(e.error, status_code=HTTP_400_BAD_REQUEST)

        if grant_user is None:
            error = "unauthorized_client"
        else:
            try:
                grant = self.get_authorization_grant(oauth2_request)
                redirect_uri = grant.validate_authorization_request()
                args = grant.create_authorization_response(redirect_uri, grant_user)
                return self.handle_response(*args)
            except InvalidGrantError as e:
                logger.debug(f"{e}", exc_info=True)
                error = "unsupported_response_type"
            except OAuth2Error as e:
                error = e.error
            except Exception as e:
                logger.error(f"unexpected exception: {e}", exc_info=True)

        params = {
            "error": error,
        }
        if oauth2_request.state is not None:
            params["state"] = oauth2_request.state

        if redirect_uri is not None:
            return RedirectResponse(add_params_to_uri(redirect_uri, params))
        else:
            return PlainTextResponse(error, status_code=HTTP_400_BAD_REQUEST)


class OpenIDConnectIdProvider:
    authz_server: AuthorizationServer
    now: typing.Callable[[], datetime]
    uuidgen: typing.Callable[[], str]

    def __init__(
        self,
        jwt_config: JWTConfiguration,
        cognito_version: int = 2,
        now: typing.Callable[[], datetime] = utcnow,
        uuidgen: typing.Callable[[], str] = lambda: str(uuid.uuid4()),
    ):
        self.jwt_config = jwt_config
        self.cognito_version = cognito_version
        self.authz_server = AuthorizationServer(
            query_client=self._get_client_by_id,
            save_token=self._save_token,
            generate_token=self._generate_token,
            jwt_config=self.jwt_config,
            now=now,
            uuidgen=uuidgen,
        )
        self.authz_server.register_grant(
            AuthorizationCodeGrant, [OpenIDCode(False), CodeChallenge(required=False)]
        )
        self.authz_server.register_grant(OpenIDImplicitGrant)
        self.jwt_builder = JsonWebToken()
        self.now = now  # type: ignore
        self.uuidgen = uuidgen  # type: ignore

    def _jwt_encode_jws(self, payload):
        header = {
            "alg": self.jwt_config.signature_algorithm,
            **self.jwt_config.signature_params,
        }
        if isinstance(self.jwt_config.key, dict) and "kid" in self.jwt_config.key:
            header["kid"] = self.jwt_config.key["kid"]
        return self.jwt_builder.encode(header, payload, self.jwt_config.key).decode(
            "ascii"
        )

    def _jwt_encode_jwe_or_jws(self, payload):
        alg: str
        params: typing.Dict[str, str]
        if self.jwt_config.encryption_algorithm is not None:
            alg = self.jwt_config.encryption_algorithm
            params = self.jwt_config.encryption_params
        else:
            alg = self.jwt_config.signature_algorithm
            params = self.jwt_config.signature_params
        header = {"alg": alg, **params}
        if isinstance(self.jwt_config.key, dict) and "kid" in self.jwt_config.key:
            header["kid"] = self.jwt_config.key["kid"]
        return self.jwt_builder.encode(header, payload, self.jwt_config.key).decode(
            "ascii"
        )

    def _get_client_by_id(self, client_id: str) -> ClientMixin:
        return get_client_by_id(client_id)

    def _save_token(self, token: TokenDict, request: OAuth2Request):
        assert isinstance(request, OAuth2Request)
        assert request.user is not None
        assert request.client is not None
        expires_at = self.now() + timedelta(  # type: ignore
            seconds=typing.cast(int, token["expires_in"])
        )
        token_obj = Token(
            pool_id=request.client.obj.pool_id,
            client=request.client.obj,
            user=request.user.obj,
            event=request.event,
            scope=" ".join(typing.cast(typing.Iterable[str], token.get("scope", ""))),
            access_token=typing.cast(str, token["access_token"]),
            refresh_token=typing.cast(
                typing.Optional[str], token.get("refresh_token", None)
            ),
            expires_at=expires_at,
        )
        session.add(token_obj)

    def _generate_access_token(
        self,
        request: OAuth2Request,
        client: ClientMixin,
        grant_type: str,
        event: Event,
        expires_in: int,
        user: typing.Optional[UserModelWrapper],
        scope: typing.Optional[str],
    ) -> str:
        assert user is not None
        created_at = event.created_at.replace(tzinfo=timezone.utc)
        return self._jwt_encode_jws(
            {
                "sub": user.obj.key,
                "cognito:groups": [g.name for g in user.obj.groups],
                "iss": self.jwt_config.issuer,
                "version": self.cognito_version,
                "client_id": client.get_client_id(),
                "auth_time": created_at.timestamp(),
                "event_id": event.key,
                "username": user.obj.key,
                "scope": scope,
                "iat": created_at.timestamp(),
                "jti": self.uuidgen(),  # type: ignore
                "token_use": "access",
                "exp": (
                    created_at.replace(tzinfo=timezone.utc)
                    + timedelta(seconds=expires_in)
                ).timestamp(),
            }
        )

    def _generate_refresh_token(
        self,
        request: OAuth2Request,
        client: ClientMixin,
        grant_type: str,
        event: Event,
        expires_in: int,
        user: typing.Optional[UserModelWrapper],
        scope: typing.Optional[str],
    ) -> str:
        assert user is not None
        return self._jwt_encode_jwe_or_jws(
            {
                "sub": user.obj.key,
                "iss": self.jwt_config.issuer,
                "version": self.cognito_version,
                "client_id": client.get_client_id(),
                "auth_time": event.created_at.timestamp(),
                "event_id": event.key,
                "username": user.obj.key,
                "scope": scope,
                "token_use": "refresh",
                "exp": (
                    event.created_at.replace(tzinfo=timezone.utc)
                    + timedelta(seconds=expires_in)
                ).timestamp(),
            }
        )

    def _get_expires_in(
        self, request: Request, client: ClientMixin, grant_type: str
    ) -> int:
        return client.obj.get_ttl_for(grant_type)

    def _generate_token(
        self,
        request: OAuth2Request,
        client: ClientMixin,
        grant_type: str,
        event: Event,
        user: typing.Optional[UserModelWrapper] = None,
        scope: typing.Optional[str] = None,
        expires_in: typing.Optional[int] = None,
        include_refresh_token: bool = True,
    ) -> TokenDict:
        return BearerToken(
            access_token_generator=self._generate_access_token,
            refresh_token_generator=self._generate_refresh_token,
            expires_generator=self._get_expires_in,
        )(
            request,
            client,
            grant_type,
            event,
            user,
            scope,
            expires_in,
            include_refresh_token,
        )

    async def create_endpoint_response(self, name: str, request: Request) -> Response:
        return await async_(self.authz_server.create_endpoint_response)(name, request)

    async def create_authorization_response(
        self, request: Request, user: typing.Optional[User]
    ) -> Response:
        grant_user = UserModelWrapper(user) if user is not None else None
        return await async_(self.authz_server.create_authorization_response)(
            request, grant_user
        )

    async def create_token_response(self, request: Request) -> Response:
        return await async_(self.authz_server.create_token_response)(request)

    async def direct_grant(
        self,
        request: Request,
        client: ClientMixin,
        user: User,
        scope: typing.Optional[str] = None,
    ) -> TokenDict:
        oauth2_request = OAuth2Request(request)
        oauth2_request.client = client
        oauth2_request.user = UserModelWrapper(user)
        oauth2_request.data["response_type"] = "code"
        oauth2_request.credential = DummyCredential(auth_time=self.now())  # type: ignore
        grant = self.authz_server.get_authorization_grant(oauth2_request)
        grant.event = oauth2_request.event
        token = grant.generate_token(
            client,
            grant_type="authorization_code",
            user=UserModelWrapper(user),
            scope=client.get_scope() if scope is None else scope,
            include_refresh_token=True,
        )
        grant.execute_hook("process_token", token=token)
        logger.debug("Grant token %r to %r", token, client)
        self._save_token(token, oauth2_request)
        return token


class TokenModelWrapper(TokenMixin):
    token_dict: typing.Mapping[str, typing.Any]

    def __init__(self, token_dict: typing.Mapping[str, typing.Any]):
        self.token_dict = token_dict

    def get_client_id(self) -> str:
        return self.token_dict["client_id"]

    def get_scope(self) -> str:
        return self.token_dict["scope"]

    def get_subject(self) -> str:
        return self.token_dict["sub"]

    def get_expires_at(self) -> typing.Union[int, float]:
        return self.token_dict["exp"]


TokenValidator = typing.Callable[[str, HttpRequest], TokenMixin]


class BearerTokenValidator(_BearerTokenValidator):
    jwt_config: JWTConfiguration
    now: typing.Callable[[], datetime]

    def __init__(
        self, now: typing.Callable[[], datetime], jwt_config: JWTConfiguration
    ):
        super().__init__(None)
        self.now = now  # type: ignore
        self.jwt_config = jwt_config

    def authenticate_token(self, token_str: str) -> TokenMixin:
        claim = JsonWebToken().decode(token_str, self.jwt_config.public_key)
        claim.validate(now=self.now().timestamp())  # type: ignore
        return TokenModelWrapper(claim)

    def request_invalid(self, request: HttpRequest) -> bool:
        return False

    def token_revoked(self, token: str) -> bool:
        return False

    def __call__(self, token_str: str, request: HttpRequest) -> TokenMixin:
        if self.request_invalid(request):
            raise InvalidRequestError()
        token = self.authenticate_token(token_str)
        host = request.headers.get("Host", "")
        if not token:
            raise InvalidTokenError(realm=host)
        if self.token_expired(token):
            raise InvalidTokenError(realm=host)
        if self.token_revoked(token):
            raise InvalidTokenError(realm=host)
        return token


class OurResourceProtector:
    _token_validators: typing.Dict[str, TokenValidator]

    def __init__(self, validators):
        self._token_validators = {
            validator.TOKEN_TYPE: validator for validator in validators
        }

    def validate_request(self, request: HttpRequest):
        auth = request.headers.get("Authorization")
        if not auth:
            raise MissingAuthorizationError()

        # https://tools.ietf.org/html/rfc6749#section-7.1
        token_parts = auth.split(None, 1)
        if len(token_parts) != 2:
            raise UnsupportedTokenTypeError()

        token_type, token = token_parts

        validator = self._token_validators.get(token_type.lower())
        if not validator:
            raise UnsupportedTokenTypeError()

        return validator(token, request)


class OAuth2AuthenticationBackend(AuthenticationBackend):
    if typing.TYPE_CHECKING:

        @staticmethod
        def now() -> datetime:
            pass

    else:
        now: typing.Callable[[], datetime] = staticmethod(utcnow)

    async def authenticate(
        self, request: HTTPConnection
    ) -> typing.Optional[typing.Tuple[AuthCredentials, BaseUser]]:
        resource_protector = OurResourceProtector(
            [BearerTokenValidator(self.now, request.app.state.jwt_config)]
        )
        try:
            token_wrap = resource_protector.validate_request(HttpRequest(request))
            user = await async_(
                session.query(User)
                .join(Client, User.pool_id == Client.pool_id)
                .filter(
                    Client.oauth2_client_id == token_wrap.get_client_id(),
                    User.key == token_wrap.get_subject(),
                )
                .one
            )()
            return (
                AuthCredentials(list(set(token_wrap.get_scope().split(None)))),
                StarletteUserWrapper(user),
            )
        except (
            ExpiredTokenError,
            InvalidTokenError,
            MissingAuthorizationError,
            UnsupportedTokenTypeError,
            orm_exc.NoResultFound,
        ) as e:
            logger.debug(str(e), exc_info=True)
            return None
