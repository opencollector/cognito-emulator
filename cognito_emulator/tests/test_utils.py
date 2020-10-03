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

import dataclasses
import typing

import pytest
import typesystem


def test_from_alien_object():
    from ..utils import from_alien_object

    class FooSchema(typesystem.Schema):
        a = typesystem.Integer()

    class BarSchema(typesystem.Schema):
        foo = typesystem.Reference(to=FooSchema)

    class BarsSchema(typesystem.Schema):
        bars = typesystem.Array(typesystem.Reference(to=BarSchema))

    @dataclasses.dataclass
    class Foo:
        a: int

    @dataclasses.dataclass
    class Bar:
        foo: Foo

    @dataclasses.dataclass
    class Bars:
        bars: typing.Sequence[Bar]

    result = from_alien_object(
        BarsSchema,
        Bars(
            bars=[
                Bar(
                    foo=Foo(a=1),
                ),
                Bar(
                    foo=Foo(a=2),
                ),
            ],
        ),
    )
    assert result == {
        "bars": [
            {
                "foo": {"a": 1},
            },
            {
                "foo": {"a": 2},
            },
        ],
    }


async def test_populate_sqlalchemy_mapped_object_with_schema_new():
    import sqlalchemy as sa
    from sqlalchemy import orm
    from sqlalchemy.ext.declarative import declarative_base

    from ..utils import populate_sqlalchemy_mapped_object_with_schema

    class FooSchema(typesystem.Schema):
        a = typesystem.Integer()

    class BarSchema(typesystem.Schema):
        id = typesystem.Integer(allow_null=True)
        foo = typesystem.Reference(to=FooSchema)

    class BarsSchema(typesystem.Schema):
        bars = typesystem.Array(typesystem.Reference(to=BarSchema))

    engine = sa.create_engine("sqlite:///")
    metadata = sa.MetaData(bind=engine)
    Base = declarative_base(metadata=metadata)

    class Foo(Base):
        __tablename__ = "foo"

        id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
        a = sa.Column(sa.Integer(), nullable=False)

    class Bar(Base):
        __tablename__ = "bar"

        id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
        foo_id = sa.Column(sa.Integer(), sa.ForeignKey(Foo.id))
        foo = orm.relationship(Foo)
        bars_id = sa.Column(sa.Integer(), sa.ForeignKey("bars.id"))

    class Bars(Base):
        __tablename__ = "bars"
        id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)

        bars = orm.relationship(Bar)

    b = Bars()
    await populate_sqlalchemy_mapped_object_with_schema(
        b.__class__,
        b,
        BarsSchema(
            bars=[
                BarSchema(
                    foo=FooSchema(a=1),
                ),
                BarSchema(
                    foo=FooSchema(a=2),
                ),
            ],
        ),
    )

    assert len(b.bars) == 2
    assert b.bars[0] is not b.bars[1]
    assert b.bars[0].foo.a == 1
    assert b.bars[1].foo.a == 2


async def test_populate_sqlalchemy_mapped_object_with_schema_update_existing():
    import sqlalchemy as sa
    from sqlalchemy import orm
    from sqlalchemy.ext.declarative import declarative_base

    from ..utils import populate_sqlalchemy_mapped_object_with_schema

    class FooSchema(typesystem.Schema):
        a = typesystem.Integer()

    class BarSchema(typesystem.Schema):
        id = typesystem.Integer(allow_null=True)
        foo = typesystem.Reference(to=FooSchema)

    class BarsSchema(typesystem.Schema):
        bars = typesystem.Array(typesystem.Reference(to=BarSchema))

    engine = sa.create_engine("sqlite:///")
    metadata = sa.MetaData(bind=engine)
    Base = declarative_base(metadata=metadata)

    class Foo(Base):
        __tablename__ = "foo"

        id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
        a = sa.Column(sa.Integer(), nullable=False)

    class Bar(Base):
        __tablename__ = "bar"

        id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)
        foo_id = sa.Column(sa.Integer(), sa.ForeignKey(Foo.id))
        foo = orm.relationship(Foo)
        bars_id = sa.Column(sa.Integer(), sa.ForeignKey("bars.id"))

    class Bars(Base):
        __tablename__ = "bars"
        id = sa.Column(sa.Integer(), primary_key=True, autoincrement=True)

        bars = orm.relationship(Bar)

    metadata.create_all()

    session = orm.Session(bind=engine)

    foos = [
        Foo(a=1),
        Foo(a=2),
    ]

    bars = [
        Bar(
            foo=foos[0],
        ),
        Bar(
            foo=foos[1],
        ),
    ]

    b = Bars(bars=bars)
    session.add(b)
    session.flush()

    await populate_sqlalchemy_mapped_object_with_schema(
        b.__class__,
        b,
        BarsSchema(
            bars=[
                BarSchema(
                    id=bars[0].id,
                    foo=FooSchema(a=3),
                ),
                BarSchema(
                    id=bars[1].id,
                    foo=FooSchema(a=4),
                ),
            ],
        ),
    )

    assert len(b.bars) == 2
    assert b.bars[0] is bars[0]
    assert b.bars[0].foo is foos[0]
    assert b.bars[0].foo.a == 3
    assert b.bars[1] is bars[1]
    assert b.bars[1].foo is foos[1]
    assert b.bars[1].foo.a == 4

    await populate_sqlalchemy_mapped_object_with_schema(
        b.__class__,
        b,
        BarsSchema(
            bars=[
                BarSchema(
                    foo=FooSchema(a=3),
                ),
                BarSchema(
                    foo=FooSchema(a=4),
                ),
            ],
        ),
    )

    assert len(b.bars) == 2
    assert b.bars[0] is not b.bars[1]
    assert b.bars[0] is not bars[0]
    assert b.bars[0].foo.a == 3
    assert b.bars[1] is not bars[1]
    assert b.bars[1].foo.a == 4


@pytest.mark.parametrize(
    ("expected", "input"),
    [
        (
            {
                "a": "1",
                "b": "2",
            },
            [
                ("a", "1"),
                ("b", "2"),
            ],
        ),
        (
            {
                "a": ["1", "2"],
            },
            [
                ("a[]", "1"),
                ("a[]", "2"),
            ],
        ),
        (
            {
                "a": ["1", "2"],
            },
            [
                ("a[]", ["1", "2"]),
            ],
        ),
        (
            {
                "a": [None, ["1", "2"], ["3", "4"]],
            },
            [
                ("a[1]", ["1", "2"]),
                ("a[2]", ["3", "4"]),
            ],
        ),
        (
            {
                "a": {
                    "b": {
                        "c": ["1", "2"],
                    },
                },
            },
            [
                ("a[b][c][]", "1"),
                ("a[b][c][]", "2"),
            ],
        ),
    ],
)
def test_coalesce_array_notated_keys(expected, input):
    from ..utils import coalesce_array_notated_keys

    assert coalesce_array_notated_keys(input) == expected
