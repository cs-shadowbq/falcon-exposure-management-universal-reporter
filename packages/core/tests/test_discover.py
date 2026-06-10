import pytest
from unittest.mock import MagicMock, patch

from femur._exceptions import FalconAPIError
from femur.discover import (
    get_all_applications,
    get_all_hosts,
    iter_applications,
    iter_applications_mac_buckets,
    iter_applications_parallel_offset,
    iter_hosts,
)

CREDS = {"client_id": "test", "client_secret": "test", "base_url": "US1"}


def make_response(resources, after=None, status_code=200):
    pagination = {"after": after} if after else {}
    return {
        "status_code": status_code,
        "body": {
            "resources": resources,
            "meta": {"pagination": pagination},
            "errors": [],
        },
    }


# ---------------------------------------------------------------------------
# iter_hosts / get_all_hosts
# ---------------------------------------------------------------------------

class TestIterHosts:
    @patch("femur.discover.Discover")
    def test_returns_hosts_single_page(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_hosts.return_value = make_response(
            [{"id": "h1"}, {"id": "h2"}]
        )
        results = list(iter_hosts(CREDS))
        assert results == [{"id": "h1"}, {"id": "h2"}]

    @patch("femur.discover.Discover")
    def test_instantiates_with_credentials(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_hosts.return_value = make_response([])
        list(iter_hosts(CREDS))
        MockDiscover.assert_called_once_with(**CREDS)

    @patch("femur.discover.Discover")
    def test_passes_fql_filter(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_hosts.return_value = make_response([])
        list(iter_hosts(CREDS, fql_filter="host.platform_name:'Windows'"))
        call_kwargs = instance.query_combined_hosts.call_args[1]
        assert call_kwargs["filter"] == "host.platform_name:'Windows'"

    @patch("femur.discover.Discover")
    def test_omits_filter_when_none(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_hosts.return_value = make_response([])
        list(iter_hosts(CREDS))
        call_kwargs = instance.query_combined_hosts.call_args[1]
        assert "filter" not in call_kwargs

    @patch("femur.discover.Discover")
    def test_passes_sort(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_hosts.return_value = make_response([])
        list(iter_hosts(CREDS, sort="hostname|asc"))
        call_kwargs = instance.query_combined_hosts.call_args[1]
        assert call_kwargs["sort"] == "hostname|asc"

    @patch("femur.discover.Discover")
    def test_passes_facet(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_hosts.return_value = make_response([])
        list(iter_hosts(CREDS, facet="internet_exposure"))
        call_kwargs = instance.query_combined_hosts.call_args[1]
        assert call_kwargs["facet"] == "internet_exposure"

    @patch("femur.discover.Discover")
    def test_paginates_using_after_token(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_hosts.side_effect = [
            make_response([{"id": "h1"}], after="token1"),
            make_response([{"id": "h2"}]),
        ]
        results = list(iter_hosts(CREDS, page_size=1))
        assert results == [{"id": "h1"}, {"id": "h2"}]
        assert instance.query_combined_hosts.call_count == 2

    @patch("femur.discover.Discover")
    def test_caps_page_size_at_1000(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_hosts.return_value = make_response([])
        list(iter_hosts(CREDS, page_size=2000))
        call_kwargs = instance.query_combined_hosts.call_args[1]
        assert call_kwargs["limit"] == 1000

    @patch("femur.discover.Discover")
    def test_raises_on_api_error(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_hosts.return_value = {
            "status_code": 403,
            "body": {
                "resources": [],
                "meta": {"pagination": {}},
                "errors": [{"code": 403, "message": "Forbidden"}],
            },
        }
        with pytest.raises(FalconAPIError) as exc_info:
            list(iter_hosts(CREDS))
        assert exc_info.value.status_code == 403


class TestGetAllHosts:
    @patch("femur.discover.Discover")
    def test_returns_list(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_hosts.return_value = make_response([{"id": "h1"}])
        result = get_all_hosts(CREDS)
        assert isinstance(result, list)
        assert result == [{"id": "h1"}]

    @patch("femur.discover.Discover")
    def test_collects_all_pages(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_hosts.side_effect = [
            make_response([{"id": "h1"}, {"id": "h2"}], after="tok"),
            make_response([{"id": "h3"}]),
        ]
        result = get_all_hosts(CREDS)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# iter_applications / get_all_applications
# ---------------------------------------------------------------------------

class TestIterApplications:
    @patch("femur.discover.Discover")
    def test_returns_applications(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_applications.return_value = make_response(
            [{"id": "app1"}, {"id": "app2"}]
        )
        results = list(iter_applications(CREDS))
        assert results == [{"id": "app1"}, {"id": "app2"}]

    @patch("femur.discover.Discover")
    def test_passes_filter(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_applications.return_value = make_response([])
        list(iter_applications(CREDS, fql_filter="name:'nginx'"))
        call_kwargs = instance.query_combined_applications.call_args[1]
        assert call_kwargs["filter"] == "name:'nginx'"

    @patch("femur.discover.Discover")
    def test_paginates(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_applications.side_effect = [
            make_response([{"id": "app1"}], after="tok"),
            make_response([{"id": "app2"}]),
        ]
        results = list(iter_applications(CREDS, page_size=1))
        assert len(results) == 2

    @patch("femur.discover.Discover")
    def test_caps_page_size_at_1000(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_applications.return_value = make_response([])
        list(iter_applications(CREDS, page_size=9999))
        call_kwargs = instance.query_combined_applications.call_args[1]
        assert call_kwargs["limit"] == 1000


class TestGetAllApplications:
    @patch("femur.discover.Discover")
    def test_returns_list(self, MockDiscover):
        instance = MockDiscover.return_value
        instance.query_combined_applications.return_value = make_response([{"id": "app1"}])
        result = get_all_applications(CREDS)
        assert isinstance(result, list)
        assert result == [{"id": "app1"}]


def make_offset_response(resources, total=None, status_code=200):
    """Build a query_applications (offset-based) response."""
    pagination = {}
    if total is not None:
        pagination["total"] = total
    return {
        "status_code": status_code,
        "body": {
            "resources": resources,
            "meta": {"pagination": pagination},
            "errors": [],
        },
    }


def make_detail_response(resources, status_code=200):
    """Build a get_applications response."""
    return {
        "status_code": status_code,
        "body": {"resources": resources, "meta": {}, "errors": []},
    }


class TestIterApplicationsParallelOffset:
    @patch("femur.discover.Discover")
    def test_returns_all_records_single_page(self, MockDiscover):
        """When all IDs fit in one page, all detail records are returned."""
        instance = MockDiscover.return_value
        # Phase 0 probe: 2 IDs, total=2
        instance.query_applications.return_value = make_offset_response(
            ["id1", "id2"], total=2
        )
        instance.get_applications.return_value = make_detail_response(
            [{"id": "id1", "name": "nginx"}, {"id": "id2", "name": "curl"}]
        )
        results = list(iter_applications_parallel_offset(CREDS))
        assert len(results) == 2
        names = {r["name"] for r in results}
        assert names == {"nginx", "curl"}

    @patch("femur.discover.Discover")
    def test_passes_fql_filter_to_id_query(self, MockDiscover):
        """fql_filter is forwarded to query_applications."""
        instance = MockDiscover.return_value
        instance.query_applications.return_value = make_offset_response([], total=0)
        list(iter_applications_parallel_offset(CREDS, fql_filter="name:'nginx'"))
        call_kwargs = instance.query_applications.call_args[1]
        assert call_kwargs.get("filter") == "name:'nginx'"

    @patch("femur.discover.Discover")
    def test_passes_facet_to_detail_query(self, MockDiscover):
        """facet is forwarded to get_applications."""
        instance = MockDiscover.return_value
        instance.query_applications.return_value = make_offset_response(
            ["id1"], total=1
        )
        instance.get_applications.return_value = make_detail_response(
            [{"id": "id1"}]
        )
        list(iter_applications_parallel_offset(CREDS, facet="host_info"))
        call_kwargs = instance.get_applications.call_args[1]
        assert call_kwargs.get("facet") == "host_info"

    @patch("femur.discover.Discover")
    def test_yields_nothing_when_environment_empty(self, MockDiscover):
        """Empty environment returns no records."""
        instance = MockDiscover.return_value
        instance.query_applications.return_value = make_offset_response([], total=0)
        results = list(iter_applications_parallel_offset(CREDS))
        assert results == []

    @patch("femur.discover.Discover")
    def test_on_page_callback_receives_total(self, MockDiscover):
        """on_page is called with grand total from Phase 0 probe."""
        instance = MockDiscover.return_value
        instance.query_applications.return_value = make_offset_response(
            ["id1"], total=1
        )
        instance.get_applications.return_value = make_detail_response([{"id": "id1"}])

        totals = []

        def on_page(n, total):
            totals.append(total)

        list(iter_applications_parallel_offset(CREDS, on_page=on_page))
        # First call is (0, total) from Phase 0; subsequent calls carry total.
        assert 1 in totals

    @patch("femur.discover.Discover")
    def test_caps_page_size_at_100(self, MockDiscover):
        """page_size > 100 is capped to 100 in query_applications calls."""
        instance = MockDiscover.return_value
        instance.query_applications.return_value = make_offset_response([], total=0)
        list(iter_applications_parallel_offset(CREDS, page_size=9999))
        call_kwargs = instance.query_applications.call_args[1]
        assert call_kwargs["limit"] == 100

    @patch("femur.discover.Discover")
    def test_falls_back_to_cursor_when_total_exceeds_offset_cap(self, MockDiscover):
        """When total > 10 000 the function falls back to query_combined_applications."""
        instance = MockDiscover.return_value
        # Phase 0 probe: total=50000 triggers the offset cap fallback.
        instance.query_applications.return_value = make_offset_response(
            ["id1"], total=50000
        )
        # Fallback uses query_combined_applications cursor (full records, no ID phase).
        instance.query_combined_applications.return_value = make_response(
            [{"id": "id1", "name": "python"}, {"id": "id2", "name": "bash"}]
        )
        results = list(iter_applications_parallel_offset(CREDS))
        # All records from cursor fallback are returned.
        assert len(results) == 2
        assert {r["name"] for r in results} == {"python", "bash"}
        # get_applications (detail phase) must NOT have been called.
        instance.get_applications.assert_not_called()

    @patch("femur.discover.Discover")
    def test_fallback_forwards_fql_filter_to_cursor(self, MockDiscover):
        """fql_filter is forwarded to query_combined_applications in fallback mode."""
        instance = MockDiscover.return_value
        instance.query_applications.return_value = make_offset_response(
            ["id1"], total=15000
        )
        instance.query_combined_applications.return_value = make_response([])
        list(iter_applications_parallel_offset(CREDS, fql_filter="name:'curl'"))
        call_kwargs = instance.query_combined_applications.call_args[1]
        assert call_kwargs.get("filter") == "name:'curl'"


class TestIterApplicationsMacBuckets:
    @patch("femur.discover.Discover")
    def test_returns_nothing_when_all_probes_empty(self, MockDiscover):
        """All 256 prefix + null probes return total=0 → no records."""
        instance = MockDiscover.return_value
        instance.query_applications.return_value = make_offset_response([], total=0)
        results = list(iter_applications_mac_buckets(CREDS))
        assert results == []
        instance.query_combined_applications.assert_not_called()

    @patch("femur.discover.Discover")
    def test_returns_records_from_non_empty_bucket(self, MockDiscover):
        """When one prefix probe is non-empty, its chain records are yielded."""
        instance = MockDiscover.return_value

        def _probe_side(**kwargs):
            filt = kwargs.get("filter", "")
            if "AB-*'" in filt:
                return make_offset_response([], total=2)
            return make_offset_response([], total=0)

        instance.query_applications.side_effect = _probe_side
        instance.query_combined_applications.return_value = make_response(
            [{"id": "r1", "name": "nginx"}, {"id": "r2", "name": "curl"}]
        )
        results = list(iter_applications_mac_buckets(CREDS))
        assert len(results) == 2
        assert {r["name"] for r in results} == {"nginx", "curl"}

    @patch("femur.discover.Discover")
    def test_fql_filter_combined_with_mac_clause(self, MockDiscover):
        """User fql_filter is AND-combined (+) with the MAC bucket FQL clause."""
        instance = MockDiscover.return_value

        def _probe_side(**kwargs):
            filt = kwargs.get("filter", "")
            if "AB-*'" in filt:
                return make_offset_response([], total=1)
            return make_offset_response([], total=0)

        instance.query_applications.side_effect = _probe_side
        instance.query_combined_applications.return_value = make_response([{"id": "r1"}])
        list(iter_applications_mac_buckets(CREDS, fql_filter="name:'nginx'"))
        call_filt = instance.query_combined_applications.call_args[1]["filter"]
        assert "name:'nginx'" in call_filt
        assert "AB-*'" in call_filt

    @patch("femur.discover.Discover")
    def test_facet_forwarded_to_combined_query(self, MockDiscover):
        """facet kwarg is forwarded to query_combined_applications."""
        instance = MockDiscover.return_value

        def _probe_side(**kwargs):
            filt = kwargs.get("filter", "")
            if "00-*'" in filt:
                return make_offset_response([], total=1)
            return make_offset_response([], total=0)

        instance.query_applications.side_effect = _probe_side
        instance.query_combined_applications.return_value = make_response([{"id": "r1"}])
        list(iter_applications_mac_buckets(CREDS, facet="host_info"))
        call_kwargs = instance.query_combined_applications.call_args[1]
        assert call_kwargs.get("facet") == "host_info"

    @patch("femur.discover.Discover")
    def test_on_page_fires_with_grand_total_after_probe(self, MockDiscover):
        """on_page(0, grand_total) is called once after all probes complete."""
        instance = MockDiscover.return_value

        def _probe_side(**kwargs):
            filt = kwargs.get("filter", "")
            if "AB-*'" in filt:
                return make_offset_response([], total=7)
            return make_offset_response([], total=0)

        instance.query_applications.side_effect = _probe_side
        instance.query_combined_applications.return_value = make_response([])

        received = []

        def on_page(n, total):
            received.append((n, total))

        list(iter_applications_mac_buckets(CREDS, on_page=on_page))
        assert (0, 7) in received

    @patch("femur.discover.Discover")
    def test_null_bucket_included_when_non_empty(self, MockDiscover):
        """Records with no MAC address are collected via the !*'*' null bucket."""
        instance = MockDiscover.return_value

        def _probe_side(**kwargs):
            filt = kwargs.get("filter", "")
            if "!*'*'" in filt:
                return make_offset_response([], total=2)
            return make_offset_response([], total=0)

        instance.query_applications.side_effect = _probe_side
        instance.query_combined_applications.return_value = make_response(
            [{"id": "null1"}, {"id": "null2"}]
        )
        results = list(iter_applications_mac_buckets(CREDS))
        assert len(results) == 2
        call_filt = instance.query_combined_applications.call_args[1]["filter"]
        assert "!*'*'" in call_filt

    @patch("femur.discover.Discover")
    def test_mac_only_filter_when_no_fql_argument(self, MockDiscover):
        """Without a user fql_filter, only the MAC clause appears in the chain filter."""
        instance = MockDiscover.return_value

        def _probe_side(**kwargs):
            filt = kwargs.get("filter", "")
            if "CD-*'" in filt:
                return make_offset_response([], total=1)
            return make_offset_response([], total=0)

        instance.query_applications.side_effect = _probe_side
        instance.query_combined_applications.return_value = make_response([{"id": "r1"}])
        list(iter_applications_mac_buckets(CREDS))
        call_filt = instance.query_combined_applications.call_args[1]["filter"]
        assert call_filt == "host.current_mac_address:*'CD-*'"

    @patch("femur.discover.Discover")
    def test_records_from_multiple_buckets_all_returned(self, MockDiscover):
        """Records from all non-empty buckets are yielded in aggregate."""
        instance = MockDiscover.return_value

        def _probe_side(**kwargs):
            filt = kwargs.get("filter", "")
            if "AB-*'" in filt or "CD-*'" in filt:
                return make_offset_response([], total=1)
            return make_offset_response([], total=0)

        instance.query_applications.side_effect = _probe_side
        # Both active buckets share this return_value, each returning 2 records.
        instance.query_combined_applications.return_value = make_response(
            [{"id": "r1"}, {"id": "r2"}]
        )
        results = list(iter_applications_mac_buckets(CREDS))
        # Two buckets × 2 records each = 4 total.
        assert len(results) == 4

    @patch("femur.discover.Discover")
    def test_on_probe_fires_per_completed_probe(self, MockDiscover):
        """on_probe(done, total) is called once per completed probe."""
        instance = MockDiscover.return_value

        def _probe_side(**kwargs):
            filt = kwargs.get("filter", "")
            if "AB-*'" in filt:
                return make_offset_response([], total=3)
            return make_offset_response([], total=0)

        instance.query_applications.side_effect = _probe_side
        instance.query_combined_applications.return_value = make_response([])

        probe_calls = []

        def on_probe(done, total):
            probe_calls.append((done, total))

        list(iter_applications_mac_buckets(CREDS, on_probe=on_probe))
        # 256 prefix probes + 1 null probe = 257 total.
        assert len(probe_calls) == 257
        # Each call's `total` is 257.
        assert all(t == 257 for _, t in probe_calls)
        # `done` increments from 1 to 257.
        done_values = sorted(d for d, _ in probe_calls)
        assert done_values == list(range(1, 258))

    @patch("femur.discover.Discover")
    def test_shared_probe_falcon_instance(self, MockDiscover):
        """All probe calls use a single Discover instance (not one per probe)."""
        instance = MockDiscover.return_value
        instance.query_applications.return_value = make_offset_response([], total=0)
        list(iter_applications_mac_buckets(CREDS))
        # Discover is constructed once for the probe phase (+ once per Phase 1
        # bucket chain, but with total=0 there are no chains).
        assert MockDiscover.call_count == 1
