import pytest
from unittest.mock import patch

from femur._exceptions import FalconAPIError
from femur.configuration import (
    DEFAULT_ASSESSMENT_FILTER,
    get_all_assessments,
    get_evaluation_logic,
    get_rule_details,
    iter_assessments,
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
# iter_assessments / get_all_assessments
# ---------------------------------------------------------------------------

class TestIterAssessments:
    @patch("femur.configuration.ConfigurationAssessment")
    def test_returns_assessments(self, MockCA):
        instance = MockCA.return_value
        instance.query_combined_assessments.return_value = make_response(
            [{"id": "a1"}, {"id": "a2"}]
        )
        results = list(iter_assessments(CREDS))
        assert results == [{"id": "a1"}, {"id": "a2"}]

    @patch("femur.configuration.ConfigurationAssessment")
    def test_instantiates_with_credentials(self, MockCA):
        instance = MockCA.return_value
        instance.query_combined_assessments.return_value = make_response([])
        list(iter_assessments(CREDS))
        MockCA.assert_called_once_with(**CREDS)

    @patch("femur.configuration.ConfigurationAssessment")
    def test_passes_fql_filter(self, MockCA):
        instance = MockCA.return_value
        instance.query_combined_assessments.return_value = make_response([])
        list(iter_assessments(CREDS, fql_filter="finding.status:'fail'"))
        call_kwargs = instance.query_combined_assessments.call_args[1]
        assert call_kwargs["filter"] == "finding.status:'fail'"

    @patch("femur.configuration.ConfigurationAssessment")
    def test_applies_default_filter_when_none_given(self, MockCA):
        instance = MockCA.return_value
        instance.query_combined_assessments.return_value = make_response([])
        list(iter_assessments(CREDS))
        call_kwargs = instance.query_combined_assessments.call_args[1]
        assert call_kwargs["filter"] == DEFAULT_ASSESSMENT_FILTER

    @patch("femur.configuration.ConfigurationAssessment")
    def test_always_sets_filter_key(self, MockCA):
        """CA API requires a filter — ensure it is always present."""
        instance = MockCA.return_value
        instance.query_combined_assessments.return_value = make_response([])
        list(iter_assessments(CREDS))
        call_kwargs = instance.query_combined_assessments.call_args[1]
        assert "filter" in call_kwargs

    @patch("femur.configuration.ConfigurationAssessment")
    def test_passes_facet_list(self, MockCA):
        instance = MockCA.return_value
        instance.query_combined_assessments.return_value = make_response([])
        list(iter_assessments(CREDS, facet=["host", "finding.rule"]))
        call_kwargs = instance.query_combined_assessments.call_args[1]
        assert call_kwargs["facet"] == ["host", "finding.rule"]

    @patch("femur.configuration.ConfigurationAssessment")
    def test_omits_facet_when_none(self, MockCA):
        instance = MockCA.return_value
        instance.query_combined_assessments.return_value = make_response([])
        list(iter_assessments(CREDS))
        call_kwargs = instance.query_combined_assessments.call_args[1]
        assert "facet" not in call_kwargs

    @patch("femur.configuration.ConfigurationAssessment")
    def test_paginates_across_pages(self, MockCA):
        instance = MockCA.return_value
        instance.query_combined_assessments.side_effect = [
            make_response([{"id": "a1"}], after="tok1"),
            make_response([{"id": "a2"}]),
        ]
        results = list(iter_assessments(CREDS, page_size=1))
        assert len(results) == 2
        assert instance.query_combined_assessments.call_count == 2

    @patch("femur.configuration.ConfigurationAssessment")
    def test_caps_page_size_at_5000(self, MockCA):
        instance = MockCA.return_value
        instance.query_combined_assessments.return_value = make_response([])
        list(iter_assessments(CREDS, page_size=9999))
        call_kwargs = instance.query_combined_assessments.call_args[1]
        assert call_kwargs["limit"] == 5000

    @patch("femur.configuration.ConfigurationAssessment")
    def test_raises_on_api_error(self, MockCA):
        instance = MockCA.return_value
        instance.query_combined_assessments.return_value = {
            "status_code": 403,
            "body": {
                "resources": [],
                "meta": {"pagination": {}},
                "errors": [{"code": 403, "message": "Forbidden"}],
            },
        }
        with pytest.raises(FalconAPIError):
            list(iter_assessments(CREDS))


class TestGetAllAssessments:
    @patch("femur.configuration.ConfigurationAssessment")
    def test_returns_list(self, MockCA):
        instance = MockCA.return_value
        instance.query_combined_assessments.return_value = make_response([{"id": "a1"}])
        result = get_all_assessments(CREDS)
        assert isinstance(result, list)
        assert result == [{"id": "a1"}]


# ---------------------------------------------------------------------------
# get_rule_details
# ---------------------------------------------------------------------------

class TestGetRuleDetails:
    @patch("femur.configuration.ConfigurationAssessment")
    def test_returns_rule_details(self, MockCA):
        instance = MockCA.return_value
        instance.get_rule_details.return_value = make_response([{"id": "r1", "name": "Rule 1"}])
        result = get_rule_details(CREDS, ["r1"])
        assert result == [{"id": "r1", "name": "Rule 1"}]

    @patch("femur.configuration.ConfigurationAssessment")
    def test_batches_at_400(self, MockCA):
        instance = MockCA.return_value
        instance.get_rule_details.return_value = make_response([{"id": "r"}])
        ids = [f"id{i}" for i in range(450)]
        get_rule_details(CREDS, ids)
        assert instance.get_rule_details.call_count == 2  # 400 + 50

    @patch("femur.configuration.ConfigurationAssessment")
    def test_first_batch_has_400_ids(self, MockCA):
        instance = MockCA.return_value
        instance.get_rule_details.return_value = make_response([])
        ids = [f"id{i}" for i in range(450)]
        get_rule_details(CREDS, ids)
        first_call_ids = instance.get_rule_details.call_args_list[0][1]["ids"]
        assert len(first_call_ids) == 400

    @patch("femur.configuration.ConfigurationAssessment")
    def test_combines_results_from_batches(self, MockCA):
        instance = MockCA.return_value
        instance.get_rule_details.side_effect = [
            make_response([{"id": "r1"}, {"id": "r2"}]),
            make_response([{"id": "r3"}]),
        ]
        result = get_rule_details(CREDS, [f"id{i}" for i in range(450)])
        assert len(result) == 3

    @patch("femur.configuration.ConfigurationAssessment")
    def test_returns_empty_for_empty_input(self, MockCA):
        result = get_rule_details(CREDS, [])
        assert result == []


# ---------------------------------------------------------------------------
# get_evaluation_logic
# ---------------------------------------------------------------------------

class TestGetEvaluationLogic:
    @patch("femur.configuration.ConfigurationAssessmentEvaluationLogic")
    def test_returns_evaluation_logic(self, MockCAEL):
        instance = MockCAEL.return_value
        instance.get_evaluation_logic.return_value = make_response([{"id": "e1"}])
        result = get_evaluation_logic(CREDS, ["e1"])
        assert result == [{"id": "e1"}]

    @patch("femur.configuration.ConfigurationAssessmentEvaluationLogic")
    def test_batches_at_400(self, MockCAEL):
        instance = MockCAEL.return_value
        instance.get_evaluation_logic.return_value = make_response([{"id": "e"}])
        ids = [f"id{i}" for i in range(450)]
        get_evaluation_logic(CREDS, ids)
        assert instance.get_evaluation_logic.call_count == 2

    @patch("femur.configuration.ConfigurationAssessmentEvaluationLogic")
    def test_returns_empty_for_empty_input(self, MockCAEL):
        result = get_evaluation_logic(CREDS, [])
        assert result == []
