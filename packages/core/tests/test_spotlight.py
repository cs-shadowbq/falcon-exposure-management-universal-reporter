import pytest
from unittest.mock import patch

from femur._exceptions import FalconAPIError
from femur.spotlight import (
    DEFAULT_VULN_FILTER,
    _SEVERITY_LEVELS,
    _SEVERITY_CATCHALL_FILTER,
    get_all_vulnerabilities,
    get_remediations,
    get_vulnerability_details,
    iter_vulnerabilities,
    iter_vulnerabilities_by_severity,
    iter_vulnerabilities_parallel,
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
# iter_vulnerabilities / get_all_vulnerabilities
# ---------------------------------------------------------------------------

class TestIterVulnerabilities:
    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_applies_default_filter_when_none_given(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([{"id": "v1"}])
        list(iter_vulnerabilities(CREDS))
        call_kwargs = instance.query_vulnerabilities_combined.call_args[1]
        assert call_kwargs["filter"] == DEFAULT_VULN_FILTER

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_uses_custom_filter_when_provided(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        list(iter_vulnerabilities(CREDS, fql_filter="cve.severity:'CRITICAL'"))
        call_kwargs = instance.query_vulnerabilities_combined.call_args[1]
        assert call_kwargs["filter"] == "cve.severity:'CRITICAL'"

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_always_sets_filter_key(self, MockSpotlight):
        """Spotlight API requires a filter — ensure it is always present."""
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        list(iter_vulnerabilities(CREDS))
        call_kwargs = instance.query_vulnerabilities_combined.call_args[1]
        assert "filter" in call_kwargs

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_returns_vulnerabilities(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response(
            [{"id": "v1"}, {"id": "v2"}]
        )
        results = list(iter_vulnerabilities(CREDS))
        assert results == [{"id": "v1"}, {"id": "v2"}]

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_paginates_across_pages(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.side_effect = [
            make_response([{"id": "v1"}], after="tok1"),
            make_response([{"id": "v2"}]),
        ]
        results = list(iter_vulnerabilities(CREDS, page_size=1))
        assert len(results) == 2
        assert instance.query_vulnerabilities_combined.call_count == 2

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_passes_sort(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        list(iter_vulnerabilities(CREDS, sort="created_timestamp|desc"))
        call_kwargs = instance.query_vulnerabilities_combined.call_args[1]
        assert call_kwargs["sort"] == "created_timestamp|desc"

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_caps_page_size_at_5000(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        list(iter_vulnerabilities(CREDS, page_size=9999))
        call_kwargs = instance.query_vulnerabilities_combined.call_args[1]
        assert call_kwargs["limit"] == 5000

    @patch("femur._pagination._MAX_AUTH_RETRIES", 0)
    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_raises_on_api_error(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = {
            "status_code": 401,
            "body": {
                "resources": [],
                "meta": {"pagination": {}},
                "errors": [{"code": 401, "message": "Unauthorized"}],
            },
        }
        with pytest.raises(FalconAPIError):
            list(iter_vulnerabilities(CREDS))


class TestGetAllVulnerabilities:
    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_returns_list(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([{"id": "v1"}])
        result = get_all_vulnerabilities(CREDS)
        assert isinstance(result, list)
        assert result == [{"id": "v1"}]


# ---------------------------------------------------------------------------
# get_vulnerability_details
# ---------------------------------------------------------------------------

class TestGetVulnerabilityDetails:
    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_returns_details(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.get_vulnerabilities.return_value = make_response([{"id": "v1", "cve": {}}])
        result = get_vulnerability_details(CREDS, ["v1"])
        assert result == [{"id": "v1", "cve": {}}]

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_batches_at_400(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.get_vulnerabilities.return_value = make_response([{"id": "v"}])
        ids = [f"id{i}" for i in range(450)]
        get_vulnerability_details(CREDS, ids)
        assert instance.get_vulnerabilities.call_count == 2  # 400 + 50

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_first_batch_has_400_ids(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.get_vulnerabilities.return_value = make_response([])
        ids = [f"id{i}" for i in range(450)]
        get_vulnerability_details(CREDS, ids)
        first_call_ids = instance.get_vulnerabilities.call_args_list[0][1]["ids"]
        assert len(first_call_ids) == 400

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_combines_results_from_all_batches(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.get_vulnerabilities.side_effect = [
            make_response([{"id": "v1"}, {"id": "v2"}]),
            make_response([{"id": "v3"}]),
        ]
        result = get_vulnerability_details(CREDS, [f"id{i}" for i in range(450)])
        assert len(result) == 3

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_returns_empty_for_empty_input(self, MockSpotlight):
        result = get_vulnerability_details(CREDS, [])
        assert result == []


# ---------------------------------------------------------------------------
# get_remediations
# ---------------------------------------------------------------------------

class TestGetRemediations:
    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_returns_remediations(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.get_remediations_v2.return_value = make_response([{"id": "r1"}])
        result = get_remediations(CREDS, ["r1"])
        assert result == [{"id": "r1"}]

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_batches_at_400(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.get_remediations_v2.return_value = make_response([{"id": "r"}])
        ids = [f"id{i}" for i in range(450)]
        get_remediations(CREDS, ids)
        assert instance.get_remediations_v2.call_count == 2

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_returns_empty_for_empty_input(self, MockSpotlight):
        result = get_remediations(CREDS, [])
        assert result == []


# ---------------------------------------------------------------------------
# iter_vulnerabilities_parallel
# ---------------------------------------------------------------------------

class TestIterVulnerabilitiesParallel:
    """Tests for the two-phase parallel vulnerability fetch strategy.

    Phase 1: ``query_vulnerabilities`` collects IDs only (fast).
    Phase 2: ``get_vulnerabilities`` fetches full records in batches.

    All tests use ``workers=1`` to keep execution deterministic and
    avoid threading concerns with mock ``side_effect`` lists.
    """

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_uses_query_vulnerabilities_for_phase1(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities.return_value = make_response([])
        list(iter_vulnerabilities_parallel(CREDS, workers=1))
        instance.query_vulnerabilities.assert_called()
        instance.query_vulnerabilities_combined.assert_not_called()

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_uses_get_vulnerabilities_for_phase2(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities.return_value = make_response(["id1", "id2"])
        instance.get_vulnerabilities.return_value = make_response(
            [{"id": "id1"}, {"id": "id2"}]
        )
        list(iter_vulnerabilities_parallel(CREDS, workers=1))
        instance.get_vulnerabilities.assert_called_once()
        ids_passed = instance.get_vulnerabilities.call_args[1]["ids"]
        assert set(ids_passed) == {"id1", "id2"}

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_returns_all_records(self, MockSpotlight):
        instance = MockSpotlight.return_value
        ids = [f"id{i}" for i in range(5)]
        records = [{"id": f"id{i}"} for i in range(5)]
        instance.query_vulnerabilities.return_value = make_response(ids)
        instance.get_vulnerabilities.return_value = make_response(records)
        results = list(iter_vulnerabilities_parallel(CREDS, workers=1))
        assert len(results) == 5

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_empty_result_when_no_ids(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities.return_value = make_response([])
        results = list(iter_vulnerabilities_parallel(CREDS, workers=1))
        assert results == []
        instance.get_vulnerabilities.assert_not_called()

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_applies_default_filter(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities.return_value = make_response([])
        list(iter_vulnerabilities_parallel(CREDS, workers=1))
        call_kwargs = instance.query_vulnerabilities.call_args[1]
        assert call_kwargs["filter"] == DEFAULT_VULN_FILTER

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_uses_custom_filter_when_provided(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities.return_value = make_response([])
        list(iter_vulnerabilities_parallel(
            CREDS, fql_filter="cve.severity:'CRITICAL'", workers=1
        ))
        call_kwargs = instance.query_vulnerabilities.call_args[1]
        assert call_kwargs["filter"] == "cve.severity:'CRITICAL'"

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_on_page_called_with_zero_total_after_phase1(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities.return_value = make_response(["id1", "id2", "id3"])
        instance.get_vulnerabilities.return_value = make_response(
            [{"id": "id1"}, {"id": "id2"}, {"id": "id3"}]
        )
        calls = []
        list(iter_vulnerabilities_parallel(
            CREDS, workers=1, on_page=lambda n, t: calls.append((n, t))
        ))
        # Post-loop signal (0, 3) must be present; batch completion (3, *) must
        # also be present.  Order is non-deterministic (worker vs main thread).
        assert (0, 3) in calls
        assert any(n == 3 for n, _ in calls)

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_on_page_called_per_batch_in_phase2(self, MockSpotlight):
        instance = MockSpotlight.return_value
        # 5 IDs with batch_size=3 → 2 batches in phase 2
        ids = [f"id{i}" for i in range(5)]
        instance.query_vulnerabilities.return_value = make_response(ids)
        instance.get_vulnerabilities.side_effect = [
            make_response([{"id": f"id{i}"} for i in range(3)]),
            make_response([{"id": f"id{i}"} for i in range(3, 5)]),
        ]
        calls = []
        list(iter_vulnerabilities_parallel(
            CREDS,
            workers=1,
            detail_batch_size=3,
            on_page=lambda n, t: calls.append((n, t)),
        ))
        # 3 calls total: 2 from _fetch_batch workers + 1 post-loop (0, 5).
        # Order is non-deterministic; verify membership not position.
        assert len(calls) == 3
        assert (0, 5) in calls  # post-loop denominator signal
        batch_calls = [(n, t) for n, t in calls if n > 0]
        assert sum(n for n, _ in batch_calls) == 5  # all 5 records accounted for

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_batches_ids_at_detail_batch_size(self, MockSpotlight):
        instance = MockSpotlight.return_value
        ids = [f"id{i}" for i in range(10)]
        instance.query_vulnerabilities.return_value = make_response(ids)
        instance.get_vulnerabilities.return_value = make_response([{"id": "v"}])
        list(iter_vulnerabilities_parallel(CREDS, workers=1, detail_batch_size=4))
        # 10 ids / 4 per batch = 3 batches (4 + 4 + 2)
        assert instance.get_vulnerabilities.call_count == 3

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_caps_id_page_size_at_400(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities.return_value = make_response([])
        list(iter_vulnerabilities_parallel(CREDS, workers=1, id_page_size=9999))
        call_kwargs = instance.query_vulnerabilities.call_args[1]
        assert call_kwargs["limit"] == 400

    # ------------------------------------------------------------------
    # on_ids_page callback (two-row progress mode)
    # ------------------------------------------------------------------

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_on_ids_page_called_once_per_phase1_page(self, MockSpotlight):
        """on_ids_page fires once per phase-1 page (not just the first)."""
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities.side_effect = [
            make_response(["id1", "id2"], after="tok"),
            make_response(["id3"]),
        ]
        instance.get_vulnerabilities.return_value = make_response(
            [{"id": "id1"}, {"id": "id2"}, {"id": "id3"}]
        )
        ids_calls: list = []
        list(iter_vulnerabilities_parallel(
            CREDS, workers=1, on_ids_page=lambda n, t: ids_calls.append((n, t))
        ))
        assert len(ids_calls) == 2
        assert ids_calls[0] == (2, None)  # 2 IDs on page 1, no api_total in mock
        assert ids_calls[1] == (1, None)  # 1 ID on page 2

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_on_ids_page_does_not_suppress_phase2_on_page(self, MockSpotlight):
        """When on_ids_page is set, on_page still fires for phase-2 batches
        and for the post-loop total signal."""
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities.return_value = make_response(["id1", "id2"])
        instance.get_vulnerabilities.return_value = make_response(
            [{"id": "id1"}, {"id": "id2"}]
        )
        page_calls: list = []
        list(iter_vulnerabilities_parallel(
            CREDS,
            workers=1,
            on_page=lambda n, t: page_calls.append((n, t)),
            on_ids_page=lambda n, t: None,
        ))
        # Post-loop fires on_page(0, 2); one phase-2 batch fires on_page(2, 2)
        assert (0, 2) in page_calls
        assert any(n == 2 for n, _ in page_calls)

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_on_ids_page_suppresses_early_on_page_from_phase1(self, MockSpotlight):
        """When on_ids_page is provided AND the API returns a total, the early
        on_page(0, api_total) signal from _on_phase1_page is suppressed.
        on_page receives: batch completions (n>0, api_total) from workers, and
        the post-loop (0, total_ids) signal.  It does NOT receive (0, api_total)
        as its first call."""
        instance = MockSpotlight.return_value
        # Inject an api_total so that single-row mode would fire on_page(0, 99) early
        instance.query_vulnerabilities.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["id1"],
                "meta": {"pagination": {"total": 99}},
                "errors": [],
            },
        }
        instance.get_vulnerabilities.return_value = make_response([{"id": "id1"}])
        page_calls: list = []
        ids_calls: list = []
        list(iter_vulnerabilities_parallel(
            CREDS,
            workers=1,
            on_page=lambda n, t: page_calls.append((n, t)),
            on_ids_page=lambda n, t: ids_calls.append((n, t)),
        ))
        # on_ids_page received the api_total from _on_phase1_page
        assert ids_calls[0] == (1, 99)
        # on_page must NOT include the suppressed early (0, 99) signal.
        assert (0, 99) not in page_calls
        # on_page does receive: post-loop (0, 1) and batch completion (1, 99).
        assert (0, 1) in page_calls
        assert any(n == 1 for n, _ in page_calls)


# ---------------------------------------------------------------------------
# iter_vulnerabilities_by_severity
# ---------------------------------------------------------------------------

class TestIterVulnerabilitiesBySeverity:
    """Tests for the severity-bucket parallel strategy.

    Five independent query_vulnerabilities_combined cursor chains run
    concurrently (CRITICAL, HIGH, MEDIUM, LOW, OTHER).  All tests patch the
    class so every bucket shares the same mock instance.
    """

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_uses_combined_endpoint_not_query(self, MockSpotlight):
        """Must use query_vulnerabilities_combined, not query_vulnerabilities."""
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        list(iter_vulnerabilities_by_severity(CREDS))
        instance.query_vulnerabilities_combined.assert_called()
        instance.query_vulnerabilities.assert_not_called()

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_five_buckets_five_calls(self, MockSpotlight):
        """One call per bucket (4 named severity levels + 1 catch-all)."""
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        list(iter_vulnerabilities_by_severity(CREDS))
        assert instance.query_vulnerabilities_combined.call_count == 5

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_each_named_severity_appears_in_a_filter(self, MockSpotlight):
        """CRITICAL, HIGH, MEDIUM, LOW each appear as a dedicated bucket filter."""
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        list(iter_vulnerabilities_by_severity(CREDS))
        all_filters = [
            kw["filter"]
            for _, kw in instance.query_vulnerabilities_combined.call_args_list
        ]
        # Each named level must appear as the exact single-value form 'LEVEL'
        # (not just as a substring of the catch-all NOT clause).
        for level in _SEVERITY_LEVELS:
            exact_clause = f"cve.severity:'{level}'"
            assert any(exact_clause in f for f in all_filters), (
                f"No bucket filter contains '{exact_clause}'"
            )

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_catchall_filter_appears_in_one_bucket(self, MockSpotlight):
        """The NOT-severity catch-all filter is used for the OTHER bucket."""
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        list(iter_vulnerabilities_by_severity(CREDS))
        all_filters = [
            kw["filter"]
            for _, kw in instance.query_vulnerabilities_combined.call_args_list
        ]
        assert any(_SEVERITY_CATCHALL_FILTER in f for f in all_filters)

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_base_filter_present_in_every_bucket(self, MockSpotlight):
        """The user's base FQL filter is embedded in every bucket's filter."""
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        custom = "status:['open','reopen']"
        list(iter_vulnerabilities_by_severity(CREDS, fql_filter=custom))
        for _, kw in instance.query_vulnerabilities_combined.call_args_list:
            assert custom in kw["filter"]

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_applies_default_filter_when_none_given(self, MockSpotlight):
        """Uses DEFAULT_VULN_FILTER as the base when fql_filter is omitted."""
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        list(iter_vulnerabilities_by_severity(CREDS))
        for _, kw in instance.query_vulnerabilities_combined.call_args_list:
            assert DEFAULT_VULN_FILTER in kw["filter"]

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_returns_combined_results_from_all_buckets(self, MockSpotlight):
        """Records from every bucket are combined in the output."""
        instance = MockSpotlight.return_value
        # One record per call → expect 5 total
        instance.query_vulnerabilities_combined.return_value = make_response(
            [{"id": "v1"}]
        )
        results = list(iter_vulnerabilities_by_severity(CREDS))
        assert len(results) == 5

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_returns_empty_when_all_buckets_empty(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        results = list(iter_vulnerabilities_by_severity(CREDS))
        assert results == []

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_caps_page_size_at_5000(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        list(iter_vulnerabilities_by_severity(CREDS, page_size=9999))
        for _, kw in instance.query_vulnerabilities_combined.call_args_list:
            assert kw["limit"] == 5000

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_passes_facet_to_every_bucket(self, MockSpotlight):
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response([])
        list(iter_vulnerabilities_by_severity(CREDS, facet="host_info"))
        for _, kw in instance.query_vulnerabilities_combined.call_args_list:
            assert kw.get("facet") == "host_info"

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_on_page_called_for_each_bucket_page(self, MockSpotlight):
        """on_page fires once per bucket page across all 5 chains."""
        instance = MockSpotlight.return_value
        # Each bucket: 1 page of 2 records (no pagination token → single page)
        instance.query_vulnerabilities_combined.return_value = make_response(
            [{"id": "a"}, {"id": "b"}]
        )
        calls = []
        list(iter_vulnerabilities_by_severity(
            CREDS, on_page=lambda n, t: calls.append((n, t))
        ))
        # 5 buckets × 1 page each → 5 on_page calls, each with n=2
        assert len(calls) == 5
        assert all(n == 2 for n, _ in calls)

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_grand_total_none_when_api_total_missing(self, MockSpotlight):
        """Grand total stays None when API responses omit pagination total."""
        instance = MockSpotlight.return_value
        instance.query_vulnerabilities_combined.return_value = make_response(
            [{"id": "v"}]
        )
        totals_seen = []
        list(iter_vulnerabilities_by_severity(
            CREDS, on_page=lambda n, t: totals_seen.append(t)
        ))
        # make_response omits "total" → api_total is None → grand always None
        assert all(t is None for t in totals_seen)

    @patch("femur.spotlight.SpotlightVulnerabilities")
    def test_grand_total_is_sum_of_bucket_totals(self, MockSpotlight):
        """When all 5 buckets report an API total the grand total is their sum."""
        instance = MockSpotlight.return_value

        def _resp_with_total(total_val):
            return {
                "status_code": 200,
                "body": {
                    "resources": [{"id": "v"}],
                    "meta": {"pagination": {"total": total_val}},
                    "errors": [],
                },
            }

        # All five buckets report total=10 → grand total should reach 50.
        instance.query_vulnerabilities_combined.return_value = _resp_with_total(10)
        totals_seen = []
        list(iter_vulnerabilities_by_severity(
            CREDS, on_page=lambda n, t: totals_seen.append(t)
        ))
        assert 50 in totals_seen
