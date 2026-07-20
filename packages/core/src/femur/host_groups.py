"""CrowdStrike Falcon Host Group API.

Requires API scope: ``host-groups:read``

Host groups are used as filter values in Discover and Spotlight queries.
Use :func:`get_host_group_ids` to look up group IDs by name, then pass those
IDs to the relevant filter parameter.

FQL filter examples for host groups
-------------------------------------
Filter groups by name::

    name:'My Group'

Filter by group type::

    group_type:'dynamic'
    group_type:'static'

FQL filter examples for group members
--------------------------------------
Filter members by platform::

    platform_name:'Windows'

Filter members by OS version::

    os_version:'Windows 11'

Using group IDs in other APIs
------------------------------
Discover hosts in a group (use group *name*)::

    host.groups:['Workstations']

Spotlight vulnerabilities for hosts in a group (use group *ID*)::

    host_info.groups:['03f0b54af2692e99c4cec945818fbef7']

Configuration assessments for hosts in a group (use group *ID*)::

    host.groups:['03f0b54af2692e99c4cec945818fbef7']

Example workflow::

    from femur import (
        load_credentials, get_host_group_ids, get_all_vulnerabilities, build_fql
    )

    creds = load_credentials("talon1.env")
    group_ids = get_host_group_ids(creds, fql_filter="name:'Production Servers'")
    group_filter = f"host_info.groups:{group_ids}"
    vulns = get_all_vulnerabilities(creds, fql_filter=build_fql(
        f"host_info.groups:{group_ids}",
        "status:['open','reopen']",
        "cve.severity:'CRITICAL'",
    ))
"""

from typing import Dict, Iterator, List, Optional, Tuple

from falconpy import HostGroup

from ._pagination import _check_response, _paginate_offset


def iter_host_groups(
    credentials: dict,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    page_size: int = 500,
) -> Iterator[dict]:
    """Iterate over all host groups matching an optional FQL filter.

    Uses offset pagination.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: FQL expression. See module docstring for examples.
        sort: Sort expression, e.g. ``"name|asc"``.
        page_size: Records per API page (max 5000).

    Yields:
        Host group resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = HostGroup(**credentials)
    kwargs: dict = {}
    if fql_filter:
        kwargs["filter"] = fql_filter
    if sort:
        kwargs["sort"] = sort
    yield from _paginate_offset(
        falcon.query_combined_host_groups,
        min(page_size, 5000),
        "query_combined_host_groups",
        **kwargs,
    )


def get_all_host_groups(
    credentials: dict,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    page_size: int = 500,
) -> List[dict]:
    """Return all host groups matching an optional FQL filter as a list.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: FQL expression.
        sort: Sort expression.
        page_size: Records per API page (max 5000).

    Returns:
        List of host group resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    return list(
        iter_host_groups(credentials, fql_filter=fql_filter, sort=sort, page_size=page_size)
    )


def iter_group_members(
    credentials: dict,
    group_id: str,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    page_size: int = 500,
) -> Iterator[dict]:
    """Iterate over all member hosts of a host group.

    Returns full host detail dicts (same schema as Discover combined hosts).
    Uses offset pagination.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        group_id: ID of the host group to enumerate.
        fql_filter: Optional FQL expression to further filter members.
        sort: Sort expression, e.g. ``"hostname|asc"``.
        page_size: Records per API page (max 5000).

    Yields:
        Host resource dicts for each member of the group.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = HostGroup(**credentials)
    kwargs: dict = {"id": group_id}
    if fql_filter:
        kwargs["filter"] = fql_filter
    if sort:
        kwargs["sort"] = sort
    yield from _paginate_offset(
        falcon.query_combined_group_members,
        min(page_size, 5000),
        "query_combined_group_members",
        **kwargs,
    )


def get_all_group_members(
    credentials: dict,
    group_id: str,
    fql_filter: Optional[str] = None,
    sort: Optional[str] = None,
    page_size: int = 500,
) -> List[dict]:
    """Return all member hosts of a host group as a list.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        group_id: ID of the host group to enumerate.
        fql_filter: Optional FQL expression to further filter members.
        sort: Sort expression.
        page_size: Records per API page (max 5000).

    Returns:
        List of host resource dicts.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    return list(
        iter_group_members(
            credentials,
            group_id=group_id,
            fql_filter=fql_filter,
            sort=sort,
            page_size=page_size,
        )
    )


def get_host_group_ids(
    credentials: dict,
    fql_filter: Optional[str] = None,
) -> List[str]:
    """Return the IDs of all host groups matching an optional FQL filter.

    This is a convenience helper for building FQL filter values for Spotlight
    and Configuration Assessment queries that accept group IDs.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        fql_filter: FQL expression to narrow results, e.g. ``"name:'Prod'"``

    Returns:
        List of host group ID strings.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    falcon = HostGroup(**credentials)
    kwargs: dict = {}
    if fql_filter:
        kwargs["filter"] = fql_filter
    return list(
        _paginate_offset(
            falcon.query_host_groups,
            5000,
            "query_host_groups",
            **kwargs,
        )
    )


def resolve_group_names_to_ids(
    credentials: dict,
    names: List[str],
) -> Tuple[Dict[str, str], List[str]]:
    """Resolve host group *names* to their group IDs.

    Spotlight and Configuration Assessment queries filter on group **ID**,
    whereas Discover filters on group **name**.  The CLI accepts group names
    only (see ``--host-groups``); this helper looks up the corresponding IDs
    so the same user input can drive all three datasets.

    A single ``query_combined_host_groups`` call is made with a comma-joined
    ``name:*'A',name:*'B'`` FQL OR-expression so the lookup costs one request
    regardless of how many names are supplied.  The ``:*`` (exact-match)
    operator is required — the Host Group API's ``name`` field does not match
    with the plain ``:`` operator, and it does not accept a ``[...]`` array —
    so each name becomes its own ``name:*'...'`` clause.  Matching is
    case-sensitive and exact.

    Args:
        credentials: Dict with ``client_id``, ``client_secret``, ``base_url``.
        names: Host group display names, e.g. ``["Cloud-Lab", "COAMS"]``.

    Returns:
        A ``(resolved, missing)`` tuple where *resolved* maps each found name
        to its group ID and *missing* lists any names with no matching group.

    Raises:
        :class:`~femur.FalconAPIError`: On API errors.
    """
    wanted = [n for n in (name.strip() for name in names) if n]
    if not wanted:
        return {}, []

    # One request. The name field requires the exact-match ``:*`` operator and
    # rejects ``name:[...]`` arrays, so OR the per-name clauses with ``,``.
    # Escape any single quotes in names.
    fql = ",".join("name:*'" + n.replace("'", "\\'") + "'" for n in wanted)

    resolved: Dict[str, str] = {}
    for group in get_all_host_groups(credentials, fql_filter=fql):
        name = group.get("name")
        gid = group.get("id")
        if name and gid and name not in resolved:
            resolved[name] = gid

    missing = [n for n in wanted if n not in resolved]
    return resolved, missing
