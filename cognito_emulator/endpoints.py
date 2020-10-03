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

import cgi
import dataclasses
import inspect
import typing

import ujson
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.status import HTTP_200_OK, HTTP_400_BAD_REQUEST
from starlette.types import Receive, Scope, Send

from .executor import as_coroutine_function

AWSPayload = typing.Mapping[str, typing.Any]
AWSPayloadResponse = typing.Union[AWSPayload, typing.Tuple[int, AWSPayload]]


DEFAULT_CONTENT_TYPE = "application/octet-stream"


@dataclasses.dataclass
class AWSEndpointTargetMetadata:
    name: str
    type: str


def amz_target(
    name: str, type_: str = "json"
) -> typing.Callable[
    [typing.Callable[..., typing.Any]], typing.Callable[..., typing.Any]
]:
    def _(f):
        f.amz_endpoint_metadata = AWSEndpointTargetMetadata(name, type_)
        return f

    return _


class AWSServerException(Exception):
    def as_aws_payload(self) -> AWSPayload:
        raise NotImplementedError()


class AWSWrappedException(AWSServerException):
    type: str

    def as_aws_payload(self) -> AWSPayload:
        return {
            "Output": {"__type": self.type},
            "Version": "1.0",
        }


class AWSBadRequest(HTTPException):
    def __init__(self):
        super().__init__(
            detail=ujson.dumps(
                {
                    "code": "BadRequest",
                    "message": "The server did not understand the operation that was requested.",
                    "type": "client",
                }
            ),
            status_code=HTTP_400_BAD_REQUEST,
        )


class UnknownOperationException(AWSWrappedException):
    type = "com.amazon.coral.service#UnknownOperationException"


class SerializationException(AWSWrappedException):
    type = "com.amazon.coral.service#SerializationException"


class AWSLikeEndpoint:
    metadata: typing.Optional[AWSEndpointTargetMetadata] = None

    def __init__(self, scope: Scope, receive: Receive, send: Send):
        assert scope["type"] == "http"
        self.scope = scope
        self.receive = receive
        self.send = send

    def __await__(self) -> typing.Generator:
        return self.dispatch().__await__()

    def get_handler(
        self, request: Request
    ) -> typing.Tuple[
        AWSEndpointTargetMetadata,
        typing.Callable[[AWSPayload], typing.Awaitable[AWSPayloadResponse]],
    ]:
        target = request.headers.get("x-amz-target")
        if target is not None:
            for k in dir(self):
                v = getattr(self, k)
                if inspect.ismethod(v):
                    metadata = getattr(v, "amz_endpoint_metadata", None)
                    if metadata and metadata.name == target:
                        return metadata, as_coroutine_function(v)
        raise AWSBadRequest()

    async def get_request_payload(
        self, request: Request, metadata: AWSEndpointTargetMetadata
    ) -> AWSPayload:
        type_, params = cgi.parse_header(
            request.headers.get("content-type", DEFAULT_CONTENT_TYPE)
        )
        encoding = params.get("charset", "utf-8")

        if metadata.type == "json":
            if (
                not type_.startswith("application/x-amz-json-")
                and type_ != "application/json"
            ):
                raise UnknownOperationException()
            text_body = (await request.body()).decode(encoding)
            try:
                return ujson.loads(text_body)
            except ValueError:
                raise SerializationException()
        elif metadata.type == "query":
            raise NotImplementedError()  # TODO
        else:
            raise ValueError()

    def encode_response(
        self, metadata: AWSEndpointTargetMetadata, payload: AWSPayloadResponse
    ) -> Response:
        if metadata.type == "json":
            status_code = HTTP_200_OK
            _payload: AWSPayload
            if isinstance(payload, tuple):
                status_code, _payload = payload
            else:
                _payload = payload
            return Response(
                content=ujson.dumps(_payload),
                status_code=status_code,
                headers={"Content-Type": "application/x-amz-json-1.1; charset=utf-8"},
            )
        elif metadata.type == "query":
            raise NotImplementedError()  # TODO
        else:
            raise ValueError()

    async def dispatch(self):
        try:
            request = Request(self.scope, self.receive)
            metadata, handler = self.get_handler(request)
            request_payload = await self.get_request_payload(request, metadata)
            self.request = request
            self.metadata = metadata
            response: Response
            response_payload = await handler(request_payload)
            response = self.encode_response(metadata, response_payload)
        except AWSServerException as e:
            response = self.encode_response(
                metadata, (HTTP_400_BAD_REQUEST, e.as_aws_payload())
            )
        await response(self.scope, self.receive, self.send)

    async def method_not_allowed(self) -> Response:
        if "app" in self.scope:
            raise HTTPException(status_code=405)
        return PlainTextResponse("Method Not Allowed", status_code=405)
