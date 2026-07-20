"""First-class host-group and tag scope filters for FEMUR.

The three datasets FEMUR fetches — Discover applications, Spotlight
vulnerabilities and Configuration Assessment findings — each expose host
group and host tag filter fields, but under **different field names** and
with **different value semantics**:

+-------------------+-------------------+------------------+-----------------+
| Dataset           | Groups field      | Tags field       | Group value     |
+===================+===================+==================+=================+
| Discover apps     | ``host.groups``   | ``host.tags``    | group **name**  |
| Spotlight vulns   | ``host_info.groups`` | ``host_info.tags`` | group **ID** |
| Config assessment | ``host.groups``   | ``host.tags``    | group **ID**    |
+-------------------+-------------------+------------------+-----------------+

The CLI exposes two dataset-agnostic flags — ``--host-groups`` and
``--tags`` — and this module maps those user inputs onto the correct field
name and value type for each dataset, then folds them into any user-supplied
``--*-filter`` FQL with a logical AND (``+``).

Group names are resolved to IDs by the caller (see
:func:`~femur.resolve_group_names_to_ids`) because only Discover accepts
names; Spotlight and Configuration Assessment require IDs.

Tag values are normalised with :func:`normalize_tag`: a bare value such as
``Monkey`` is prefixed to ``FalconGroupingTags/Monkey``, while a value that
already carries a ``prefix/`` segment (e.g. ``SensorGroupingTags/web``) is
used verbatim.
"""

from typing import List, Optional

from ._pagination import build_fql

# Per-dataset FQL field names for the group and tag scope filters.
# ``groups_by`` records whether the dataset matches groups by ``name`` or
# ``id`` so the CLI can supply the correct value list.
DATASET_SCOPE_FIELDS = {
    "applications": {"groups": "host.groups", "tags": "host.tags", "groups_by": "name"},
    "vulnerabilities": {"groups": "host_info.groups", "tags": "host_info.tags", "groups_by": "id"},
    "assessments": {"groups": "host.groups", "tags": "host.tags", "groups_by": "id"},
}

DEFAULT_TAG_PREFIX = "FalconGroupingTags"
"""Prefix applied to bare tag values that carry no ``prefix/`` segment."""


def normalize_tag(tag: str) -> str:
    """Normalise a single ``--tags`` value to a full grouping-tag value.

    A value that already contains a ``/`` is assumed to carry its own prefix
    (``FalconGroupingTags/x``, ``SensorGroupingTags/y``, or any future
    ``prefix/value`` form) and is returned unchanged.  A bare value is
    prefixed with :data:`DEFAULT_TAG_PREFIX`.

    Args:
        tag: Raw tag value from the CLI, e.g. ``"Monkey"`` or
            ``"SensorGroupingTags/web"``.

    Returns:
        The normalised tag value, e.g. ``"FalconGroupingTags/Monkey"``.
    """
    tag = tag.strip()
    if "/" in tag:
        return tag
    return f"{DEFAULT_TAG_PREFIX}/{tag}"


def _fql_array(field: str, values: List[str]) -> str:
    """Build an FQL ``field:['a','b']`` OR-clause, or ``""`` if no values.

    Single quotes inside values are backslash-escaped so a value cannot break
    out of the quoted literal.
    """
    cleaned = [v for v in (val.strip() for val in values) if v]
    if not cleaned:
        return ""
    quoted = ",".join("'" + v.replace("'", "\\'") + "'" for v in cleaned)
    return f"{field}:[{quoted}]"


def build_scope_clause(
    dataset: str,
    group_values: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> str:
    """Build the combined group + tag FQL clause for a single *dataset*.

    Groups and tags are each rendered as a single OR array clause and joined
    with ``+`` (AND).  So ``--host-groups "A,B" --tags "x"`` yields, for
    applications, ``host.groups:['A','B']+host.tags:['FalconGroupingTags/x']``
    — a host in group A *or* B that *also* carries tag x.

    Args:
        dataset: One of ``"applications"``, ``"vulnerabilities"``,
            ``"assessments"``.
        group_values: Group values already in the form this dataset expects
            (names for applications, IDs for vulns/assessments).
        tags: Raw tag values from the CLI; normalised via :func:`normalize_tag`.

    Returns:
        A single FQL expression, or ``""`` if no scope values were supplied.

    Raises:
        KeyError: If *dataset* is not a known dataset name.
    """
    fields = DATASET_SCOPE_FIELDS[dataset]
    clauses: List[str] = []
    if group_values:
        clauses.append(_fql_array(fields["groups"], group_values))
    if tags:
        clauses.append(_fql_array(fields["tags"], [normalize_tag(t) for t in tags]))
    return build_fql(*clauses)


def augment_filter(
    base_filter: Optional[str],
    dataset: str,
    group_values: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> Optional[str]:
    """Fold group/tag scope clauses into an existing *base_filter* with AND.

    The scope clause is additive: it is appended to whatever the user passed
    via ``--app-filter`` / ``--vuln-filter`` / ``--assessment-filter`` (and to
    the library default when the user passed nothing).  When no group or tag
    values are supplied, *base_filter* is returned unchanged.

    Args:
        base_filter: The dataset's current FQL filter, or ``None``.
        dataset: One of the keys in :data:`DATASET_SCOPE_FIELDS`.
        group_values: Group values in this dataset's expected form.
        tags: Raw tag values from the CLI.

    Returns:
        The combined filter string, or ``None`` if both inputs were empty.
    """
    scope = build_scope_clause(dataset, group_values=group_values, tags=tags)
    if not scope:
        return base_filter
    if base_filter:
        return build_fql(base_filter, scope)
    return scope
