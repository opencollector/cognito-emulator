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

import srp  # type: ignore
import typesystem
from sqlalchemy.orm import exc as orm_exc
from starlette.requests import Request

from ...db import session
from ...endpoints import (
    AWSLikeEndpoint,
    AWSPayload,
    AWSPayloadResponse,
    AWSServerException,
    UnknownOperationException,
    amz_target,
)
from ...executor import async_
from ...utils import StrEnum
from ..models import Client, User
from ..oidc import EVENT_KEY, ClientModelWrapper, TokenDict
from ..types import KeyDerivationFunction
from .oauth2 import get_id_provider, new_event


class AuthFlowType(StrEnum):
    USER_SRP_AUTH = "USER_SRP_AUTH"
    REFRESH_TOKEN_AUTH = "REFRESH_TOKEN_AUTH"
    REFRESH_TOKEN = "REFRESH_TOKEN"
    CUSTOM_AUTH = "CUSTOM_AUTH"
    ADMIN_NO_SRP_AUTH = "ADMIN_NO_SRP_AUTH"
    USER_PASSWORD_AUTH = "USER_PASSWORD_AUTH"


class ChallengeNameType(StrEnum):
    SMS_MFA = "SMS_MFA"
    SOFTWARE_TOKEN_MFA = "SOFTWARE_TOKEN_MFA"
    SELECT_MFA_TYPE = "SELECT_MFA_TYPE"
    MFA_SETUP = "MFA_SETUP"
    PASSWORD_VERIFIER = "PASSWORD_VERIFIER"
    CUSTOM_CHALLENGE = "CUSTOM_CHALLENGE"
    DEVICE_SRP_AUTH = "DEVICE_SRP_AUTH"
    DEVICE_PASSWORD_VERIFIER = "DEVICE_PASSWORD_VERIFIER"
    ADMIN_NO_SRP_AUTH = "ADMIN_NO_SRP_AUTH"
    NEW_PASSWORD_REQUIRED = "NEW_PASSWORD_REQUIRED"


class AnalyticsMetadataType(typesystem.Schema):
    AnalyticsEndpointId = typesystem.String()


class UserContextDataType(typesystem.Schema):
    EncodedData = typesystem.String()


class InitiateAuthRequest(typesystem.Schema):
    AuthFlow = typesystem.Choice(choices=list(AuthFlowType))
    AuthParameters = typesystem.Object()
    ClientMetadata = typesystem.Object(allow_null=True)
    ClientId = typesystem.String()
    AnalyticsMetadata = typesystem.Reference(AnalyticsMetadataType, allow_null=True)
    UserContextData = typesystem.Reference(UserContextDataType, allow_null=True)


class NewDeviceMetadataType(typesystem.Schema):
    DeviceKey = typesystem.String(min_length=1, max_length=55)
    DeviceGroupKey = typesystem.String()


class AuthenticationResultType(typesystem.Schema):
    AccessToken = typesystem.String(pattern=r"[A-Za-z0-9_=.-]+")
    ExpiresIn = typesystem.Integer()
    TokenType = typesystem.String()
    RefreshToken = typesystem.String(pattern=r"[A-Za-z0-9_=.-]+")
    IdToken = typesystem.String(pattern=r"[A-Za-z0-9_=.-]+")
    NewDeviceMetadata = typesystem.Reference(NewDeviceMetadataType, allow_null=True)


class InitiateAuthResponse(typesystem.Schema):
    ChallengeName = typesystem.Choice(choices=list(ChallengeNameType), allow_null=True)
    Session = typesystem.String(max_length=2048, allow_null=True)
    ChallengeParameters = typesystem.Object(allow_null=True)
    AuthenticationResult = typesystem.Reference(
        AuthenticationResultType, allow_null=True
    )


class InvalidParameterException(AWSServerException):
    message: typing.Optional[str]

    def __init__(self, message: typing.Optional[str] = None):
        super().__init__()
        self.message = message

    def as_aws_payload(self) -> AWSPayload:
        return {
            "__type": "InvalidParameterException",
            "message": self.message,
        }


class NotAuthorizedException(AWSServerException):
    message: typing.Optional[str]

    def __init__(self, message: typing.Optional[str] = None):
        super().__init__()
        self.message = message

    def as_aws_payload(self) -> AWSPayload:
        return {
            "__type": "NotAuthorizedException",
            "message": self.message,
        }


class AuthFlowHandler:
    request: Request
    client: Client

    def __init__(self, request: Request, client: Client):
        self.request = request
        self.client = client

    def get_srp_verifier(self, username: str, srp_a: str) -> srp.Verifier:
        return srp.Verifier(
            username,
            self.request.app.state.srp_salt,
            self.request.app.state.srp_verifier_key,
            srp_a,
        )

    @property
    def kdf(self) -> KeyDerivationFunction:
        return self.request.app.state.kdf

    async def direct_grant(self, user: User) -> TokenDict:
        self.request.scope[EVENT_KEY] = await async_(new_event)(self.client.pool)
        client = ClientModelWrapper(self.client)
        id_provider = get_id_provider(self.request, client)
        return await id_provider.direct_grant(self.request, client, user)

    async def handle_user_srp_auth(
        self, initiate_auth_req: InitiateAuthRequest
    ) -> InitiateAuthResponse:
        pass

    async def handle_refresh_token_auth(
        self, initiate_auth_req: InitiateAuthRequest
    ) -> InitiateAuthResponse:
        pass

    async def handle_custom_auth(
        self, initiate_auth_req: InitiateAuthRequest
    ) -> InitiateAuthResponse:
        raise NotImplementedError()

    async def handle_admin_no_srp_auth(
        self, initiate_auth_req: InitiateAuthRequest
    ) -> InitiateAuthResponse:
        raise NotImplementedError()

    async def handle_user_password_auth(
        self, initiate_auth_req: InitiateAuthRequest
    ) -> InitiateAuthResponse:
        try:
            username = initiate_auth_req.AuthParameters["USERNAME"]  # type: ignore
        except KeyError:
            raise InvalidParameterException("Missing required parameter USERNAME")

        try:
            password = initiate_auth_req.AuthParameters["PASSWORD"]  # type: ignore
        except KeyError:
            raise InvalidParameterException("Missing required parameter PASSWORD")
        try:
            user = await async_(lambda: self.client.pool.query_user(username).one())()
        except orm_exc.NoResultFound:
            raise NotAuthorizedException("Incorrect username or password.")
        if not self.kdf.verify(user.password, password):
            raise NotAuthorizedException("Incorrect username or password.")

        tokens = await self.direct_grant(user)
        return InitiateAuthResponse(
            AuthenticationResult=AuthenticationResultType(
                AccessToken=tokens["access_token"],
                ExpiresIn=tokens["expires_in"],
                TokenType=tokens["token_type"],
                IdToken=tokens["id_token"],
                RefreshToken=tokens["refresh_token"],
            )
        )

    async def __call__(
        self, initiate_auth_req: InitiateAuthRequest
    ) -> InitiateAuthResponse:
        return await typing.cast(
            typing.Callable[
                [InitiateAuthRequest], typing.Awaitable[InitiateAuthResponse]
            ],
            getattr(self, f"handle_{initiate_auth_req.AuthFlow.lower()}"),  # type: ignore
        )(initiate_auth_req)


class CognitoIdProviderEndpoint(AWSLikeEndpoint):
    def get_auth_flow_handler(self, client: Client):
        return AuthFlowHandler(self.request, client)

    @amz_target("AWSCognitoIdentityProviderService.InitiateAuth")
    async def initiate_auth(self, req_payload: AWSPayload) -> AWSPayloadResponse:
        try:
            initiate_auth_req = InitiateAuthRequest.validate(req_payload)
        except typesystem.ValidationError:
            raise UnknownOperationException()
        try:
            client = await async_(
                lambda: session.query(Client)
                .filter_by(oauth2_client_id=initiate_auth_req.ClientId)  # type: ignore
                .one()
            )()
        except orm_exc.NoResultFound:
            raise InvalidParameterException()
        auth_flow_handler = self.get_auth_flow_handler(client)
        return dict(await auth_flow_handler(initiate_auth_req))


endpoint_handler = CognitoIdProviderEndpoint
