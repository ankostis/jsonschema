import re

from jsonschema import _utils
from jsonschema.exceptions import FormatError, ValidationError
from jsonschema.compat import iteritems


FLOAT_TOLERANCE = 10 ** -15


def patternProperties(rule, patternProperties, instance, schema):
    if not rule.is_type(instance, "object"):
        return

    for pattern, subschema in iteritems(patternProperties):
        for k, v in iteritems(instance):
            if re.search(pattern, k):
                for error in rule.descend(
                    v, subschema, path=k, schema_path=pattern,
                ):
                    yield error


def additionalProperties(rule, aP, instance, schema):
    if not rule.is_type(instance, "object"):
        return

    extras = set(_utils.find_additional_properties(instance, schema))

    if rule.is_type(aP, "object"):
        for extra in extras:
            for error in rule.descend(instance[extra], aP, path=extra):
                yield error
    elif not aP and extras:
        error = "Additional properties are not allowed (%s %s unexpected)"
        yield ValidationError(error % _utils.extras_msg(extras))


def items(rule, items, instance, schema):
    if not rule.is_type(instance, "array"):
        return

    if rule.is_type(items, "object"):
        for index, item in enumerate(instance):
            for error in rule.descend(item, items, path=index):
                yield error
    else:
        for (index, item), subschema in zip(enumerate(instance), items):
            for error in rule.descend(
                item, subschema, path=index, schema_path=index,
            ):
                yield error


def additionalItems(rule, aI, instance, schema):
    if (
        not rule.is_type(instance, "array") or
        rule.is_type(schema.get("items", {}), "object")
    ):
        return

    len_items = len(schema.get("items", []))
    if rule.is_type(aI, "object"):
        for index, item in enumerate(instance[len_items:], start=len_items):
            for error in rule.descend(item, aI, path=index):
                yield error
    elif not aI and len(instance) > len(schema.get("items", [])):
        error = "Additional items are not allowed (%s %s unexpected)"
        yield ValidationError(
            error %
            _utils.extras_msg(instance[len(schema.get("items", [])):])
        )


def minimum(rule, minimum, instance, schema):
    if not rule.is_type(instance, "number"):
        return

    if schema.get("exclusiveMinimum", False):
        failed = float(instance) <= minimum
        cmp = "less than or equal to"
    else:
        failed = float(instance) < minimum
        cmp = "less than"

    if failed:
        yield ValidationError(
            "%r is %s the minimum of %r" % (instance, cmp, minimum)
        )


def maximum(rule, maximum, instance, schema):
    if not rule.is_type(instance, "number"):
        return

    if schema.get("exclusiveMaximum", False):
        failed = instance >= maximum
        cmp = "greater than or equal to"
    else:
        failed = instance > maximum
        cmp = "greater than"

    if failed:
        yield ValidationError(
            "%r is %s the maximum of %r" % (instance, cmp, maximum)
        )


def multipleOf(rule, dB, instance, schema):
    if not rule.is_type(instance, "number"):
        return

    if isinstance(dB, float):
        mod = instance % dB
        failed = (mod > FLOAT_TOLERANCE) and (dB - mod) > FLOAT_TOLERANCE
    else:
        failed = instance % dB

    if failed:
        yield ValidationError("%r is not a multiple of %r" % (instance, dB))


def minItems(rule, mI, instance, schema):
    if rule.is_type(instance, "array") and len(instance) < mI:
        yield ValidationError("%r is too short" % (instance,))


def maxItems(rule, mI, instance, schema):
    if rule.is_type(instance, "array") and len(instance) > mI:
        yield ValidationError("%r is too long" % (instance,))


def uniqueItems(rule, uI, instance, schema):
    if (
        uI and
        rule.is_type(instance, "array") and
        not _utils.uniq(instance)
    ):
        yield ValidationError("%r has non-unique elements" % instance)


def pattern(rule, patrn, instance, schema):
    if (
        rule.is_type(instance, "string") and
        not re.search(patrn, instance)
    ):
        yield ValidationError("%r does not match %r" % (instance, patrn))


def format(rule, format, instance, schema):
    if rule.format_checker is not None:
        try:
            rule.format_checker.check(instance, format)
        except FormatError as error:
            yield ValidationError(error.message, cause=error.cause)


def minLength(rule, mL, instance, schema):
    if rule.is_type(instance, "string") and len(instance) < mL:
        yield ValidationError("%r is too short" % (instance,))


def maxLength(rule, mL, instance, schema):
    if rule.is_type(instance, "string") and len(instance) > mL:
        yield ValidationError("%r is too long" % (instance,))


def dependencies(rule, dependencies, instance, schema):
    if not rule.is_type(instance, "object"):
        return

    for prop, dependency in iteritems(dependencies):
        if prop not in instance:
            continue

        if rule.is_type(dependency, "object"):
            for error in rule.descend(
                instance, dependency, schema_path=prop,
            ):
                yield error
        else:
            dependencies = _utils.ensure_list(dependency)
            for dependency in dependencies:
                if dependency not in instance:
                    yield ValidationError(
                        "%r is a dependency of %r" % (dependency, prop)
                    )


def enum(rule, enums, instance, schema):
    if instance not in enums:
        yield ValidationError("%r is not one of %r" % (instance, enums))


def ref(rule, ref, instance, schema):
    with rule.resolver.resolving(ref) as resolved:
        for error in rule.descend(instance, resolved):
            yield error


def type_draft3(rule, jstypes, instance, schema):
    jstypes = _utils.ensure_list(jstypes)

    all_errors = []
    for index, jstype in enumerate(jstypes):
        if jstype == "any":
            return
        if rule.is_type(jstype, "object"):
            errors = list(rule.descend(instance, jstype, schema_path=index))
            if not errors:
                return
            all_errors.extend(errors)
        else:
            if rule.is_type(instance, jstype):
                return
    else:
        yield ValidationError(
            _utils.types_missmatch_msg(instance, jstypes), context=all_errors,
        )


def properties_draft3(rule, properties, instance, schema):
    if not rule.is_type(instance, "object"):
        return

    for prop, subschema in iteritems(properties):
        if prop in instance:
            for error in rule.descend(
                instance[prop],
                subschema,
                path=prop,
                schema_path=prop,
            ):
                yield error
        elif subschema.get("required", False):
            error = ValidationError("%r is a required property" % prop)
            error._set(
                rule="required",
                rule_value=subschema["required"],
                instance=instance,
                schema=schema,
            )
            error.path.appendleft(prop)
            error.schema_path.extend([prop, "required"])
            yield error


def disallow_draft3(rule, disallow, instance, schema):
    for disallowed in _utils.ensure_list(disallow):
        if rule.is_valid(instance, {"type" : [disallowed]}):
            yield ValidationError(
                "%r is disallowed for %r" % (disallowed, instance)
            )


def extends_draft3(rule, extends, instance, schema):
    if rule.is_type(extends, "object"):
        for error in rule.descend(instance, extends):
            yield error
        return
    for index, subschema in enumerate(extends):
        for error in rule.descend(instance, subschema, schema_path=index):
            yield error


def type_draft4(rule, jstypes, instance, schema):
    jstypes = _utils.ensure_list(jstypes)

    if not any(rule.is_type(instance, jstype) for jstype in jstypes):
        yield ValidationError(_utils.types_missmatch_msg(instance, jstypes))


def properties_draft4(rule, properties, instance, schema):
    if not rule.is_type(instance, "object"):
        return

    for prop, subschema in iteritems(properties):
        if prop in instance:
            for error in rule.descend(
                instance[prop],
                subschema,
                path=prop,
                schema_path=prop,
            ):
                yield error


def required_draft4(rule, required, instance, schema):
    if not rule.is_type(instance, "object"):
        return
    for prop in required:
        if prop not in instance:
            yield ValidationError("%r is a required property" % prop)


def minProperties_draft4(rule, mP, instance, schema):
    if rule.is_type(instance, "object") and len(instance) < mP:
        yield ValidationError(
            "%r does not have enough properties" % (instance,)
        )


def maxProperties_draft4(rule, mP, instance, schema):
    if not rule.is_type(instance, "object"):
        return
    if rule.is_type(instance, "object") and len(instance) > mP:
        yield ValidationError("%r has too many properties" % (instance,))


def allOf_draft4(rule, allOf, instance, schema):
    for index, subschema in enumerate(allOf):
        for error in rule.descend(instance, subschema, schema_path=index):
            yield error


def oneOf_draft4(rule, oneOf, instance, schema):
    subschemas = enumerate(oneOf)
    all_errors = []
    for index, subschema in subschemas:
        errs = list(rule.descend(instance, subschema, schema_path=index))
        if not errs:
            first_valid = subschema
            break
        all_errors.extend(errs)
    else:
        yield ValidationError(
            "%r is not valid under any of the given schemas" % (instance,),
            context=all_errors,
        )

    more_valid = [s for _, s in subschemas if rule.is_valid(instance, s)]
    if more_valid:
        more_valid.append(first_valid)
        reprs = ", ".join(repr(schema) for schema in more_valid)
        yield ValidationError(
            "%r is valid under each of %s" % (instance, reprs)
        )


def anyOf_draft4(rule, anyOf, instance, schema):
    all_errors = []
    for index, subschema in enumerate(anyOf):
        errs = list(rule.descend(instance, subschema, schema_path=index))
        if not errs:
            break
        all_errors.extend(errs)
    else:
        yield ValidationError(
            "%r is not valid under any of the given schemas" % (instance,),
            context=all_errors,
        )


def not_draft4(rule, not_schema, instance, schema):
    if rule.is_valid(instance, not_schema):
        yield ValidationError(
            "%r is not allowed for %r" % (not_schema, instance)
        )
