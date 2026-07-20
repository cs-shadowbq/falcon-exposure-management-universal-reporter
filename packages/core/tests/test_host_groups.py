import pytest
from unittest.mock import patch

from femur._exceptions import FalconAPIError
from femur.host_groups import (
    get_all_group_members,
    get_all_host_groups,
    get_host_group_ids,
    iter_group_members,
    iter_host_groups,
    resolve_group_names_to_ids,
)

CREDS = {"client_id": "test", "client_secret": "test", "base_url": "US1"}


def make_response(resources, status_code=200):
    """Build a falconpy offset-pagination response (no after token)."""
    return {
        "status_code": status_code,
        "body": {
            "resources": resources,
            "meta": {"pagination": {}},
            "errors": [],
        },
    }


# ---------------------------------------------------------------------------
# iter_host_groups / get_all_host_groups
# ---------------------------------------------------------------------------

class TestIterHostGroups:
    @patch("femur.host_groups.HostGroup")
    def test_returns_host_groups(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = make_response(
            [{"id": "g1"}, {"id": "g2"}]
        )
        results = list(iter_host_groups(CREDS))
        assert results == [{"id": "g1"}, {"id": "g2"}]

    @patch("femur.host_groups.HostGroup")
    def test_instantiates_with_credentials(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = make_response([])
        list(iter_host_groups(CREDS))
        MockHG.assert_called_once_with(**CREDS)

    @patch("femur.host_groups.HostGroup")
    def test_passes_fql_filter(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = make_response([])
        list(iter_host_groups(CREDS, fql_filter="group_type:'dynamic'"))
        call_kwargs = instance.query_combined_host_groups.call_args[1]
        assert call_kwargs["filter"] == "group_type:'dynamic'"

    @patch("femur.host_groups.HostGroup")
    def test_omits_filter_when_none(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = make_response([])
        list(iter_host_groups(CREDS))
        call_kwargs = instance.query_combined_host_groups.call_args[1]
        assert "filter" not in call_kwargs

    @patch("femur.host_groups.HostGroup")
    def test_passes_sort(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = make_response([])
        list(iter_host_groups(CREDS, sort="name|asc"))
        call_kwargs = instance.query_combined_host_groups.call_args[1]
        assert call_kwargs["sort"] == "name|asc"

    @patch("femur.host_groups.HostGroup")
    def test_uses_offset_pagination(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.side_effect = [
            make_response([{"id": "g1"}, {"id": "g2"}]),
            make_response([{"id": "g3"}]),
        ]
        results = list(iter_host_groups(CREDS, page_size=2))
        assert results == [{"id": "g1"}, {"id": "g2"}, {"id": "g3"}]
        assert instance.query_combined_host_groups.call_count == 2

    @patch("femur.host_groups.HostGroup")
    def test_second_page_has_correct_offset(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.side_effect = [
            make_response([{"id": "g1"}, {"id": "g2"}]),
            make_response([{"id": "g3"}]),
        ]
        list(iter_host_groups(CREDS, page_size=2))
        second_call_kwargs = instance.query_combined_host_groups.call_args_list[1][1]
        assert second_call_kwargs["offset"] == 2

    @patch("femur.host_groups.HostGroup")
    def test_caps_page_size_at_5000(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = make_response([])
        list(iter_host_groups(CREDS, page_size=9999))
        call_kwargs = instance.query_combined_host_groups.call_args[1]
        assert call_kwargs["limit"] == 5000

    @patch("femur.host_groups.HostGroup")
    def test_raises_on_api_error(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = {
            "status_code": 403,
            "body": {
                "resources": [],
                "meta": {},
                "errors": [{"code": 403, "message": "Forbidden"}],
            },
        }
        with pytest.raises(FalconAPIError):
            list(iter_host_groups(CREDS))


class TestGetAllHostGroups:
    @patch("femur.host_groups.HostGroup")
    def test_returns_list(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = make_response([{"id": "g1"}])
        result = get_all_host_groups(CREDS)
        assert isinstance(result, list)
        assert result == [{"id": "g1"}]


# ---------------------------------------------------------------------------
# iter_group_members / get_all_group_members
# ---------------------------------------------------------------------------

class TestIterGroupMembers:
    @patch("femur.host_groups.HostGroup")
    def test_returns_members(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_group_members.return_value = make_response(
            [{"id": "h1"}, {"id": "h2"}]
        )
        results = list(iter_group_members(CREDS, group_id="grp123"))
        assert results == [{"id": "h1"}, {"id": "h2"}]

    @patch("femur.host_groups.HostGroup")
    def test_passes_group_id_as_id_param(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_group_members.return_value = make_response([])
        list(iter_group_members(CREDS, group_id="grp123"))
        call_kwargs = instance.query_combined_group_members.call_args[1]
        assert call_kwargs["id"] == "grp123"

    @patch("femur.host_groups.HostGroup")
    def test_passes_fql_filter_for_members(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_group_members.return_value = make_response([])
        list(iter_group_members(CREDS, group_id="grp123", fql_filter="platform_name:'Linux'"))
        call_kwargs = instance.query_combined_group_members.call_args[1]
        assert call_kwargs["filter"] == "platform_name:'Linux'"

    @patch("femur.host_groups.HostGroup")
    def test_uses_offset_pagination(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_group_members.side_effect = [
            make_response([{"id": "h1"}, {"id": "h2"}]),
            make_response([{"id": "h3"}]),
        ]
        results = list(iter_group_members(CREDS, group_id="grp123", page_size=2))
        assert len(results) == 3
        assert instance.query_combined_group_members.call_count == 2


class TestGetAllGroupMembers:
    @patch("femur.host_groups.HostGroup")
    def test_returns_list(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_group_members.return_value = make_response([{"id": "h1"}])
        result = get_all_group_members(CREDS, group_id="grp123")
        assert isinstance(result, list)
        assert result == [{"id": "h1"}]


# ---------------------------------------------------------------------------
# get_host_group_ids
# ---------------------------------------------------------------------------

class TestGetHostGroupIds:
    @patch("femur.host_groups.HostGroup")
    def test_returns_list_of_id_strings(self, MockHG):
        instance = MockHG.return_value
        instance.query_host_groups.return_value = make_response(["id1", "id2", "id3"])
        result = get_host_group_ids(CREDS)
        assert result == ["id1", "id2", "id3"]

    @patch("femur.host_groups.HostGroup")
    def test_passes_fql_filter(self, MockHG):
        instance = MockHG.return_value
        instance.query_host_groups.return_value = make_response([])
        get_host_group_ids(CREDS, fql_filter="name:'Production'")
        call_kwargs = instance.query_host_groups.call_args[1]
        assert call_kwargs["filter"] == "name:'Production'"

    @patch("femur.host_groups.HostGroup")
    def test_paginates_via_offset(self, MockHG):
        instance = MockHG.return_value
        page1 = [f"id{i}" for i in range(5000)]
        page2 = ["id5000", "id5001"]
        instance.query_host_groups.side_effect = [
            make_response(page1),
            make_response(page2),
        ]
        result = get_host_group_ids(CREDS)
        assert len(result) == 5002
        assert instance.query_host_groups.call_count == 2

    @patch("femur.host_groups.HostGroup")
    def test_returns_empty_list_when_no_groups(self, MockHG):
        instance = MockHG.return_value
        instance.query_host_groups.return_value = make_response([])
        result = get_host_group_ids(CREDS)
        assert result == []

    @patch("femur.host_groups.HostGroup")
    def test_raises_on_api_error(self, MockHG):
        instance = MockHG.return_value
        instance.query_host_groups.return_value = {
            "status_code": 403,
            "body": {
                "resources": [],
                "meta": {},
                "errors": [{"code": 403, "message": "Forbidden"}],
            },
        }
        with pytest.raises(FalconAPIError):
            get_host_group_ids(CREDS)


# ---------------------------------------------------------------------------
# resolve_group_names_to_ids
# ---------------------------------------------------------------------------

class TestResolveGroupNamesToIds:
    @patch("femur.host_groups.HostGroup")
    def test_resolves_names_to_ids(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = make_response(
            [
                {"name": "Cloud Lab", "id": "dfba0b1b823e46409f069711d151be0c"},
                {"name": "Development", "id": "aaa111"},
            ]
        )
        resolved, missing = resolve_group_names_to_ids(
            CREDS, ["Cloud Lab", "Development"]
        )
        assert resolved == {
            "Cloud Lab": "dfba0b1b823e46409f069711d151be0c",
            "Development": "aaa111",
        }
        assert missing == []

    @patch("femur.host_groups.HostGroup")
    def test_single_query_with_name_array(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = make_response([])
        resolve_group_names_to_ids(CREDS, ["Cloud Lab", "Development"])
        # Exactly one API request regardless of the number of names.
        assert instance.query_combined_host_groups.call_count == 1
        call_kwargs = instance.query_combined_host_groups.call_args[1]
        assert call_kwargs["filter"] == "name:*'Cloud Lab',name:*'Development'"

    @patch("femur.host_groups.HostGroup")
    def test_reports_missing_names(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = make_response(
            [{"name": "Cloud Lab", "id": "abc"}]
        )
        resolved, missing = resolve_group_names_to_ids(
            CREDS, ["Cloud Lab", "Nonexistent"]
        )
        assert resolved == {"Cloud Lab": "abc"}
        assert missing == ["Nonexistent"]

    @patch("femur.host_groups.HostGroup")
    def test_empty_input_makes_no_call(self, MockHG):
        instance = MockHG.return_value
        resolved, missing = resolve_group_names_to_ids(CREDS, [])
        assert resolved == {}
        assert missing == []
        instance.query_combined_host_groups.assert_not_called()

    @patch("femur.host_groups.HostGroup")
    def test_escapes_single_quotes_in_names(self, MockHG):
        instance = MockHG.return_value
        instance.query_combined_host_groups.return_value = make_response([])
        resolve_group_names_to_ids(CREDS, ["O'Brien Lab"])
        call_kwargs = instance.query_combined_host_groups.call_args[1]
        assert call_kwargs["filter"] == "name:*'O\\'Brien Lab'"
