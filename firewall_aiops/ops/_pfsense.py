"""Resolving a pfSense object's numeric id from its name.

The pfSense REST API addresses a *singular* object by numeric ``id`` only.
Passing the human name instead is rejected outright::

    {"code": 400, "response_id": "MODEL_REQUIRES_ID",
     "message": "Field `id` is required."}

Plural endpoints do accept a field filter (``?name=web_servers``) and return
the matching records, so a name is resolved by filtering the collection and
reading the id off the single match. Verified against pfSense CE 2.7.2 with
pfSense-pkg-RESTAPI 2.4_3.

OPNsense addresses the same objects by name or UUID directly and never calls
into this module.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops._util import as_obj, pick, s


def resolve_by_name(conn: Any, resource: str, name: str, /, **fmt: Any) -> dict:
    """Return the single pfSense record whose name is ``name``.

    ``resource`` is a logical path key whose template filters a *plural*
    endpoint by name; ``fmt`` fills that template. The first three parameters
    are positional-only so a template placeholder literally called ``name``
    (aliases use one) cannot collide with this function's own argument.

    Raises ``ValueError`` when nothing matches — a missing
    object is a caller error worth stating, not an empty result to be silently
    carried into a write that would then do something else.
    """
    rows = conn.platform.rows(conn.get(conn.platform.path(resource, **fmt)))
    wanted = s(name, 64)
    for row in rows:
        if s(pick(row, "name"), 64) == wanted:
            return as_obj(row)
    raise ValueError(
        f"No {resource.split('_')[0]} named {wanted!r} exists on this firewall. "
        f"List them first and use a name from that list."
    )


def object_id(record: dict) -> int:
    """Return a resolved record's numeric ``id``.

    Raises ``ValueError`` rather than defaulting: an id of ``0`` is a real,
    common pfSense id (collections are zero-indexed), so a missing id must not
    fall back to a value that happens to address the first object.
    """
    value = pick(record, "id")
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"pfSense returned a record without a usable numeric id (got {value!r}); "
            f"cannot address it for a write."
        )
    return value
