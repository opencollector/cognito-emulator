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

import collections.abc
import enum
import functools
import itertools
import re
import typing
from collections import defaultdict

import sqlalchemy as sa
import typesystem
from sqlalchemy import orm as orm
from sqlalchemy.ext.associationproxy import AssociationProxy

from ..executor import async_


class SQLALchemyMappedObject(typing.Protocol):
    pass


def from_alien_object(
    schema: typing.Type[typesystem.Schema], obj: object
) -> typing.Dict[str, typing.Any]:
    def _serialize(
        field: typing.Union[typesystem.Field, typing.Type[typesystem.Schema]],
        value: typing.Any,
    ) -> typing.Any:
        if isinstance(field, type) and issubclass(field, typesystem.schemas.Schema):
            if isinstance(value, (collections.abc.Mapping, collections.abc.Iterable)):
                return dict(field(value))
            else:
                return from_alien_object(field, value)
        elif isinstance(field, typesystem.Array):
            if value is None:
                return None
            if not isinstance(value, collections.abc.Iterable):
                raise TypeError
            if isinstance(field.items, collections.abc.Sequence):
                return [
                    _serialize(serializer, _value)
                    for serializer, _value in zip(field.items, value)
                ]
            if field.items is None:
                return value
            return [_serialize(field.items, _value) for _value in value]
        elif isinstance(field, typesystem.Reference):
            return _serialize(field.target, value)
        else:
            mapper = object_mapper(value)
            if mapper is not None:
                return encode_primary_key_tuple(extract_primary_key_tuple(value))
            else:
                return field.serialize(value)

    return {
        key: _serialize(schema.fields[key], getattr(obj, key)) for key in schema.fields
    }


@functools.lru_cache
def columns_to_properties_map(
    mapper: orm.Mapper,
) -> typing.Mapping[
    sa.Column, typing.Sequence[typing.Union[orm.ColumnProperty, orm.CompositeProperty]]
]:
    column_to_property_mappings: typing.Dict[
        sa.Column, typing.List[typing.Union[orm.ColumnProperty, orm.CompositeProperty]]
    ] = defaultdict(list)
    for attr in mapper.attrs.values():  # type: ignore
        if isinstance(attr, orm.CompositeProperty):
            for c in attr.cols:
                column_to_property_mappings[c].append(attr)
        elif isinstance(attr, orm.ColumnProperty):
            if isinstance(attr.expression, sa.Column):
                column_to_property_mappings[attr.expression].append(attr)
    return column_to_property_mappings


@functools.lru_cache
def primary_key_properties(
    mapper: orm.Mapper,
) -> typing.Set[typing.Union[orm.ColumnProperty, orm.CompositeProperty]]:
    m = columns_to_properties_map(mapper)
    return set(itertools.chain.from_iterable(m[c] for c in mapper.primary_key))


def extract_primary_key_tuple(
    obj: SQLALchemyMappedObject,
) -> typing.Tuple[typing.Any, ...]:
    return tuple(
        getattr(obj, p.key) for p in primary_key_properties(orm.object_mapper(obj))
    )


def encode_primary_key_tuple(pt: typing.Tuple[typing.Any, ...]) -> str:
    return "\t".join(str(v) for v in pt)


def decode_primary_key_tuple(
    tr: str, mapper: orm.Mapper
) -> typing.Tuple[typing.Any, ...]:
    _decoded = tr.split("\t")
    primary_key_props = primary_key_properties(mapper)
    if len(_decoded) != len(primary_key_props):
        raise ValueError(f"invalid id tuple: {tr}")
    return tuple(
        p.expression.type.python_type(j) for j, p in zip(_decoded, primary_key_props)
    )


def object_mapper(obj: SQLALchemyMappedObject) -> typing.Optional[orm.Mapper]:
    try:
        return orm.object_mapper(obj)
    except orm.exc.UnmappedInstanceError:
        return None


T = typing.TypeVar("T")


async def populate_sqlalchemy_mapped_object_with_schema(
    target_class: typing.Type[T],
    target: typing.Optional[T],
    instance: typesystem.Schema,
    update_primary_key=False,
    create_objects=True,
    session: typing.Optional[orm.Session] = None,
) -> typing.Optional[T]:
    async def update_property_with_fields(
        target: SQLALchemyMappedObject,
        mapper: orm.Mapper,
        attr: orm.interfaces.MapperProperty,
        instance: typesystem.Schema,
    ):
        if isinstance(attr, orm.ColumnProperty):
            try:
                v = getattr(instance, attr.key)
            except AttributeError:
                return
            setattr(target, attr.key, v)
        elif isinstance(attr, orm.RelationshipProperty):
            try:
                f = instance.fields[attr.key]
                v = getattr(instance, attr.key)
            except (KeyError, AttributeError):
                return
            target_mapper = orm.class_mapper(attr.entity.entity)
            primary_key_props = primary_key_properties(target_mapper)

            if (
                attr.direction in (orm.interfaces.ONETOMANY, orm.interfaces.MANYTOMANY)
                and attr.uselist
            ):
                if not isinstance(f, typesystem.Array):
                    raise TypeError()
                if v is None:
                    raise TypeError()
                current_value = getattr(target, attr.key)
                if current_value is None:
                    raise TypeError()
                existings_map = {
                    tuple(getattr(i, p.key) for p in primary_key_props): i
                    for i in current_value
                }
                new_items = []
                for i in v:
                    id_: typing.Optional[typing.Tuple[typing.Any, ...]]
                    if isinstance(i, str):
                        # id tuple
                        id_ = decode_primary_key_tuple(i, target_mapper)
                        existing = existings_map.get(id_)
                        if existing:
                            new_items.append(existing)
                        else:
                            assert session is not None
                            new_item = await async_(
                                session.query(attr.entity)
                                .filter_by(
                                    **{p.key: v for p, v in zip(primary_key_props, id_)}
                                )
                                .one
                            )()
                            new_items.append(new_item)
                    elif isinstance(i, typesystem.Schema):
                        try:
                            id_ = tuple(getattr(i, p.key) for p in primary_key_props)
                        except AttributeError:
                            id_ = None
                        existing = existings_map.get(id_) if id_ is not None else None
                        new_item = await populate_sqlalchemy_mapped_object_with_schema(
                            existing.__class__
                            if existing is not None
                            else attr.entity.entity,
                            existing,
                            i,
                            update_primary_key=update_primary_key,
                            create_objects=create_objects,
                        )
                        if new_item is None:
                            raise RuntimeError()
                        new_items.append(new_item)
                    else:
                        _target_mapper = object_mapper(i)
                        if _target_mapper is not target_mapper:
                            raise TypeError(repr(type(i)))
                        new_items.append(i)
                getattr(target, attr.key)[:] = new_items
            elif attr.direction == orm.interfaces.MANYTOONE:
                if not isinstance(f, typesystem.Reference):
                    return TypeError()
                existing_id = tuple(getattr(target, p.key) for p in primary_key_props)
                # id_: typing.Optional[typing.Tuple[typing.Any, ...]]
                try:
                    id_ = tuple(getattr(instance, p.key) for p in primary_key_props)
                except AttributeError:
                    id_ = None
                if id_ == existing_id:
                    existing = getattr(target, attr.key)
                else:
                    existing = attr.entity.entity()
                new_obj = await populate_sqlalchemy_mapped_object_with_schema(
                    existing.__class__ if existing is not None else attr.entity.entity,
                    existing,
                    v,
                    update_primary_key=update_primary_key,
                    create_objects=create_objects,
                )
                setattr(target, attr.key, new_obj)
            else:
                raise AssertionError()

    mapper = orm.class_mapper(target_class)
    primary_key_props = primary_key_properties(mapper)

    if target is None:
        if not create_objects:
            return None
        target = target_class()

    id_: typing.Optional[typing.Tuple[typing.Any, ...]]
    try:
        id_ = tuple(getattr(instance, p.key) for p in primary_key_props)
    except AttributeError:
        id_ = None
    existing_id = tuple(getattr(target, p.key) for p in primary_key_props)

    for attr in mapper.attrs.values():
        await update_property_with_fields(target, mapper, attr, instance)

    for k, prop in mapper.all_orm_descriptors.items():
        if isinstance(prop, AssociationProxy):
            if k not in instance:
                continue
            v = getattr(instance, k)
            proxy = getattr(target, k)
            if hasattr(proxy, "update"):
                proxy.clear()
                proxy.update(v)
            else:
                proxy[:] = v
                if len(proxy) < len(v):
                    for i in range(len(proxy)):
                        if i < len(v):
                            if proxy[i] != v[i]:
                                proxy[i] = v[i]
                    for i in range(len(proxy), len(v)):
                        proxy.append(v[i])
                else:
                    for i in range(len(v)):
                        if i < len(proxy):
                            proxy[i] = v[i]
                    del proxy[len(v) :]
    if update_primary_key and id_ != existing_id:
        for attr in primary_key_props:
            await update_property_with_fields(target, mapper, attr, instance)

    return target


class FormObject(typesystem.Object):
    def __init__(
        self,
        **kwargs: typing.Any,
    ) -> None:
        super().__init__(**kwargs)

    def validate(self, value: typing.Any, *, strict: bool = False) -> typing.Any:
        if value is None and self.allow_null:
            return None
        elif value is None:
            raise self.validation_error("null")
        elif not isinstance(value, (dict, typing.Mapping)):
            raise self.validation_error("type")

        orig_value = value
        validated = {}
        error_messages = []

        # Ensure all property keys are strings.
        for key in value.keys():
            if not isinstance(key, str):
                text = self.get_error_text("invalid_key")
                message = typesystem.Message(text=text, code="invalid_key", index=[key])
                error_messages.append(message)
            elif self.property_names is not None:
                _, error = self.property_names.validate_or_error(key)
                if error is not None:
                    text = self.get_error_text("invalid_property")
                    message = typesystem.Message(
                        text=text, code="invalid_property", index=[key]
                    )
                    error_messages.append(message)

        # Boolean Properties
        for key, child_schema in self.properties.items():
            if isinstance(child_schema, typesystem.Boolean) and key not in value:
                if value is orig_value:
                    value = dict(orig_value)
                value[key] = False

        # Min/Max properties
        if self.min_properties is not None:
            if len(value) < self.min_properties:
                if self.min_properties == 1:
                    raise self.validation_error("empty")
                else:
                    raise self.validation_error("min_properties")
        if self.max_properties is not None:
            if len(value) > self.max_properties:
                raise self.validation_error("max_properties")

        # Required properties
        for key in self.required:
            if key not in value:
                text = self.get_error_text("required")
                message = typesystem.Message(text=text, code="required", index=[key])
                error_messages.append(message)

        # Properties
        for key, child_schema in self.properties.items():
            if key not in value:
                if child_schema.has_default():
                    validated[key] = child_schema.get_default_value()
                continue
            item = value[key]
            child_value, error = child_schema.validate_or_error(item, strict=strict)
            if not error:
                validated[key] = child_value
            else:
                error_messages += error.messages(add_prefix=key)

        # Pattern properties
        if self.pattern_properties:
            for key in list(value.keys()):
                for pattern, child_schema in self.pattern_properties.items():
                    if isinstance(key, str) and re.search(pattern, key):
                        item = value[key]
                        child_value, error = child_schema.validate_or_error(
                            item, strict=strict
                        )
                        if not error:
                            validated[key] = child_value
                        else:
                            error_messages += error.messages(add_prefix=key)

        # Additional properties
        validated_keys = set(validated.keys())
        error_keys = set(
            [message.index[0] for message in error_messages if message.index]
        )

        remaining = [
            key for key in value.keys() if key not in validated_keys | error_keys
        ]

        if self.additional_properties is True:
            for key in remaining:
                validated[key] = value[key]
        elif self.additional_properties is False:
            for key in remaining:
                text = self.get_error_text("invalid_property")
                message = typesystem.Message(
                    text=text, code="invalid_property", key=key
                )
                error_messages.append(message)
        elif self.additional_properties is not None:
            assert isinstance(self.additional_properties, typesystem.Field)
            child_schema = self.additional_properties
            for key in remaining:
                item = value[key]
                child_value, error = child_schema.validate_or_error(item, strict=strict)
                if not error:
                    validated[key] = child_value
                else:
                    error_messages += error.messages(add_prefix=key)

        if error_messages:
            raise typesystem.ValidationError(messages=error_messages)

        return validated


TSchema = typing.TypeVar("TSchema", bound=typesystem.Schema)


def make_validator(
    schema_type: typing.Type[TSchema], *, strict: bool = False
) -> typesystem.Field:
    required = [
        key for key, value in schema_type.fields.items() if not value.has_default()
    ]
    return FormObject(
        properties=schema_type.fields,
        required=required,
        additional_properties=False if strict else None,
    )


BRACKET_REX = re.compile(r"([^[]*)((?:\[[^]]*\])+)$")

Subscribable = typing.Union[
    typing.Sequence[typing.Any], typing.Mapping[str, typing.Any]
]


def assign_inner(
    anchor: Subscribable, k: str, paths: typing.Iterable[str], v: typing.Any
):
    it = iter(paths)

    ki: typing.Optional[int] = None
    try:
        ki = int(k)
    except ValueError:
        pass

    while True:
        new_ = False

        if k == "" or ki is not None:
            if isinstance(anchor, (str, collections.abc.Mapping)):
                raise TypeError()
            elif not isinstance(anchor, collections.abc.MutableSequence):
                raise TypeError()
            if k == "":
                ki = len(anchor)
            else:
                if typing.TYPE_CHECKING:
                    assert ki is not None
            for i in range(len(anchor), ki + 1):
                anchor.append(None)
                new_ = True
        else:
            if not isinstance(anchor, collections.abc.Mapping):
                raise TypeError()
            new_ = k not in anchor

        try:
            nk = next(it)
        except StopIteration:
            break

        nki: typing.Optional[int] = None
        try:
            nki = int(nk)
        except ValueError:
            pass

        if new_:
            c: Subscribable
            if nk == "" or nki is not None:
                c = []
            else:
                c = {}
            if ki is not None:
                if typing.TYPE_CHECKING:
                    assert isinstance(anchor, collections.abc.MutableSequence)
                anchor[ki] = c
            else:
                if typing.TYPE_CHECKING:
                    assert isinstance(anchor, collections.abc.MutableMapping)
                anchor[k] = c
            anchor = c
        else:
            if ki is not None:
                if typing.TYPE_CHECKING:
                    assert isinstance(anchor, collections.abc.MutableSequence)
                anchor = anchor[ki]
            else:
                if typing.TYPE_CHECKING:
                    assert isinstance(anchor, collections.abc.MutableMapping)
                anchor = anchor[k]
        k = nk
        ki = nki

    if ki is not None:
        if typing.TYPE_CHECKING:
            assert isinstance(anchor, collections.abc.MutableSequence)
        if (
            not isinstance(v, (str, collections.abc.MutableMapping))
            and isinstance(v, collections.abc.MutableSequence)
            and k == ""
        ):
            del anchor[-1]
            anchor.extend(v)
        else:
            anchor[ki] = v
    else:
        if typing.TYPE_CHECKING:
            assert isinstance(anchor, collections.abc.MutableMapping)
        anchor[k] = v


def coalesce_array_notated_keys(
    values: typing.Sequence[typing.Tuple[str, typing.Any]]
) -> typing.Mapping[str, typing.Any]:
    result: typing.Dict[str, typing.Any] = {}
    for k, v in values:
        m = BRACKET_REX.match(k)
        if m is not None:
            _k = m.group(1)
            subs = m.group(2)
            paths = subs[1:-1].split("][")
            assign_inner(result, _k, paths, v)
        else:
            if k in result:
                raise TypeError()
            result[k] = v
    return result


def validate_form(
    schema_type: typing.Type[TSchema],
    values: typing.Sequence[typing.Tuple[str, typing.Any]],
    *,
    strict: bool = False,
) -> TSchema:
    validator = make_validator(schema_type, strict=strict)
    return schema_type(validator.validate(values, strict=strict))


class Form(typesystem.forms.Form):
    def template_for_field(self, field: typesystem.Field) -> str:
        if isinstance(field, typesystem.Array):
            if isinstance(
                field.items,
                (
                    typesystem.String,
                    typesystem.Integer,
                    typesystem.Float,
                    typesystem.Decimal,
                ),
            ):
                return "forms/array_of_inputs.html"
            elif isinstance(field.items, (typesystem.Choice, ObjectChoice)):
                return "forms/array_of_selects.html"
        return super().template_for_field(field)

    def render_field(
        self,
        *,
        field_name: str,
        field: typesystem.Field,
        value: typing.Any = None,
        error: str = None,
    ) -> str:
        field_id_prefix = "form-" + self.schema.__name__.lower() + "-"
        field_id = field_id_prefix + field_name.replace("_", "-")
        label = field.title or field_name
        allow_empty = field.allow_null or getattr(field, "allow_blank", False)
        required = not field.has_default() and not allow_empty
        input_type = self.input_type_for_field(field)
        template_name = self.template_for_field(field)
        template = self.env.get_template(template_name)
        return template.render(
            {
                "field_id": field_id,
                "field_name": field_name,
                "field": field,
                "label": label,
                "required": required,
                "input_type": input_type,
                "value": value,
                "error": error,
            }
        )


class Jinja2Forms(typesystem.forms.Jinja2Forms):
    def Form(
        self,
        schema: typing.Type[typesystem.Schema],
        *,
        values: dict = None,
        errors: typesystem.ValidationError = None,
    ) -> Form:  # type: ignore
        return Form(env=self.env, schema=schema, values=values, errors=errors)


class Choice(typesystem.Choice):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.choices = [
            (v, (l.name if isinstance(l, enum.Enum) else l)) for v, l in self.choices
        ]

    def validate(self, value: typing.Any, *, strict: bool = False) -> typing.Any:
        if value is None and self.allow_null:
            return None
        elif value is None:
            raise self.validation_error("null")
        elif value not in typesystem.unique.Uniqueness(
            [str(key) for key, value in self.choices]
        ):
            if value == "":
                if self.allow_null and not strict:
                    return None
                raise self.validation_error("required")
            raise self.validation_error("choice")
        return value


class ObjectChoice(typesystem.Field):
    errors = {
        "null": "May not be null.",
        "required": "This field is required.",
        "choice": "Not a valid choice.",
    }

    orig_choices: typing.Sequence[typing.Tuple[str, SQLALchemyMappedObject]]

    def __init__(self, **kwargs):
        stringizer = kwargs.pop("stringizer", str)
        choices = kwargs.pop("choices", [])
        super().__init__(**kwargs)
        self.orig_choices = [(self.render_key(obj), obj) for obj in choices]
        self.stringizer = stringizer
        self.orig_choices_map = dict(self.orig_choices)

    def render_key(self, obj: SQLALchemyMappedObject) -> str:
        return encode_primary_key_tuple(extract_primary_key_tuple(obj))

    @property
    def choices(self):
        return [(k, self.stringizer(v)) for k, v in self.orig_choices]

    def validate(self, value: typing.Any, *, strict: bool = False) -> typing.Any:
        if value is None and self.allow_null:
            return None
        elif value is None:
            raise self.validation_error("null")
        elif value not in typesystem.unique.Uniqueness(
            [str(key) for key, value in self.choices]
        ):
            if value == "":
                if self.allow_null and not strict:
                    return None
                raise self.validation_error("required")
            raise self.validation_error("choice")
        return value
