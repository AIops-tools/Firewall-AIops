"""Integer quantities must stay exact integers.

Line-wide invariant, asserted per repo because the helper is vendored per repo.
It exists because of a live defect in proxy-aiops (Traefik route priority is an
int64; routing it through the float helper collapsed two *different*
priorities — …806 and …805 — onto the same displayed value). A 2026-08-02 sweep
found that only proxy-aiops had actually been fixed: five other ``as_int``
implementations, this one included, still round-tripped integers through
float64, which cannot represent values above 2**53 exactly.

The bool case is not pedantry: ``bool`` subclasses ``int``, so an int
short-circuit placed before a bool guard would return ``True`` unchanged and
serialise it as ``true`` instead of a number.
"""

from __future__ import annotations

import pytest

from firewall_aiops.ops._util import as_int


@pytest.mark.unit
def test_as_int_never_round_trips_an_int_through_float64():
    hi = 9007199254740993  # 2**53 + 1 — the smallest int a float64 cannot hold
    lo = 9007199254740992
    assert as_int(hi) == hi
    assert as_int(hi) != as_int(lo), "distinct counts must not collapse"
    # What the float path would have done, kept as the reason this test exists:
    assert int(float(hi)) == int(float(lo))


@pytest.mark.unit
def test_as_int_returns_a_real_int_not_a_bool():
    result = as_int(True)
    assert not isinstance(result, bool), "bool subclasses int; it is not a quantity"
    assert result == 0


@pytest.mark.unit
def test_as_int_types_and_edges():
    assert isinstance(as_int("42"), int) and as_int("42") == 42
    assert as_int(3.9) == 3
    assert as_int(None) == 0
    assert as_int("nonsense") == 0
