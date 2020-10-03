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

import asyncio
import concurrent.futures
import contextvars
import typing

executor: typing.Optional[concurrent.futures.ThreadPoolExecutor] = None


T = typing.TypeVar("T")


def wrap_call_soon(
    loop: asyncio.AbstractEventLoop, sync_fn: typing.Callable[[], T]
) -> typing.Awaitable[T]:
    f = _get_event_loop().create_future()

    def _():
        try:
            f.set_result(sync_fn())
        except Exception as e:
            f.set_exception(e)

    h = loop.call_soon(_)
    orig_cancel = f.cancel

    def _cancel():
        h.cancel()
        orig_cancel()

    f.cancel = _cancel  # type: ignore
    return f


def async_(
    sync_fn: typing.Callable[..., T]
) -> typing.Callable[..., typing.Awaitable[T]]:
    if executor is not None:
        ctx = contextvars.copy_context()
        return lambda *args, **kwargs: _get_event_loop().run_in_executor(
            executor, lambda: ctx.run(sync_fn, *args, **kwargs)
        )
    else:
        return lambda *args, **kwargs: wrap_call_soon(
            _get_event_loop(), lambda: sync_fn(*args, **kwargs)
        )


def _get_event_loop() -> asyncio.AbstractEventLoop:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


def await_(awaitable: typing.Awaitable[T]) -> T:
    # create another event loop within the same thread
    old_loop: typing.Optional[asyncio.AbstractEventLoop]
    try:
        old_loop = asyncio.get_running_loop()
    except RuntimeError:
        old_loop = None
    asyncio._set_running_loop(None)
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(awaitable)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            loop.close()
            asyncio.set_event_loop(old_loop)
            asyncio._set_running_loop(old_loop)


T2 = typing.TypeVar("T2")


def as_coroutine_function(
    handler: typing.Union[
        typing.Callable[..., T2], typing.Callable[..., typing.Awaitable[T2]]
    ]
) -> typing.Callable[..., typing.Awaitable[T2]]:
    if asyncio.iscoroutinefunction(handler):
        return typing.cast(typing.Callable[..., typing.Awaitable[T2]], handler)
    else:
        return async_(typing.cast(typing.Callable[..., T2], handler))
