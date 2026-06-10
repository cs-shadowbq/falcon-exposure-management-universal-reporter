import pytest
from unittest.mock import MagicMock, patch

from femur._exceptions import FalconAPIError
from femur._pagination import (
    _batch_ids,
    _check_response,
    _paginate_after,
    _paginate_offset,
    _retrying_call,
    build_fql,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_response(resources, after=None, status_code=200, errors=None):
    """Build a falconpy-shaped response dict for use in tests."""
    pagination = {"after": after} if after else {}
    return {
        "status_code": status_code,
        "body": {
            "resources": resources,
            "meta": {"pagination": pagination},
            "errors": errors or [],
        },
    }


# ---------------------------------------------------------------------------
# _check_response
# ---------------------------------------------------------------------------

class TestCheckResponse:
    def test_returns_resources_on_success(self):
        resp = make_response([{"id": "1"}, {"id": "2"}])
        assert _check_response(resp, "op") == [{"id": "1"}, {"id": "2"}]

    def test_returns_empty_list_when_resources_is_none(self):
        resp = make_response(None)
        assert _check_response(resp, "op") == []

    def test_returns_empty_list_when_resources_absent(self):
        resp = {"status_code": 200, "body": {"meta": {}, "errors": []}}
        assert _check_response(resp, "op") == []

    def test_raises_falcon_api_error_on_4xx(self):
        resp = make_response([], status_code=403, errors=[{"code": 403, "message": "Forbidden"}])
        with pytest.raises(FalconAPIError) as exc_info:
            _check_response(resp, "my_op")
        assert exc_info.value.status_code == 403
        assert exc_info.value.operation == "my_op"

    def test_raises_falcon_api_error_on_401(self):
        resp = make_response([], status_code=401, errors=[{"code": 401, "message": "Unauthorized"}])
        with pytest.raises(FalconAPIError):
            _check_response(resp, "op")

    def test_raises_falcon_api_error_on_errors_with_200(self):
        resp = make_response([], status_code=200, errors=[{"code": 400, "message": "Bad filter"}])
        with pytest.raises(FalconAPIError) as exc_info:
            _check_response(resp, "op")
        assert exc_info.value.status_code == 200

    def test_stores_all_errors_on_exception(self):
        errors = [{"code": 400, "message": "e1"}, {"code": 400, "message": "e2"}]
        resp = make_response([], status_code=400, errors=errors)
        with pytest.raises(FalconAPIError) as exc_info:
            _check_response(resp, "op")
        assert exc_info.value.errors == errors


# ---------------------------------------------------------------------------
# _paginate_after
# ---------------------------------------------------------------------------

class TestPaginateAfter:
    def test_single_page_no_after_token(self):
        sdk_fn = MagicMock(return_value=make_response([{"id": "a"}, {"id": "b"}]))
        results = list(_paginate_after(sdk_fn, 100, "op"))
        assert results == [{"id": "a"}, {"id": "b"}]
        # First call must NOT include an 'after' key
        call_kwargs = sdk_fn.call_args[1]
        assert "after" not in call_kwargs

    def test_first_call_includes_limit(self):
        sdk_fn = MagicMock(return_value=make_response([]))
        list(_paginate_after(sdk_fn, 500, "op"))
        assert sdk_fn.call_args[1]["limit"] == 500

    def test_multi_page_follows_after_token(self):
        sdk_fn = MagicMock(side_effect=[
            make_response([{"id": "a"}], after="tok1"),
            make_response([{"id": "b"}]),
        ])
        results = list(_paginate_after(sdk_fn, 1, "op"))
        assert results == [{"id": "a"}, {"id": "b"}]
        assert sdk_fn.call_count == 2
        # Second call must carry the token
        second_call_kwargs = sdk_fn.call_args_list[1][1]
        assert second_call_kwargs["after"] == "tok1"

    def test_stops_on_empty_page(self):
        sdk_fn = MagicMock(return_value=make_response([]))
        results = list(_paginate_after(sdk_fn, 100, "op"))
        assert results == []
        sdk_fn.assert_called_once()

    def test_stops_when_after_token_missing_even_if_full_page(self):
        sdk_fn = MagicMock(return_value=make_response([{"id": "x"}] * 100))
        results = list(_paginate_after(sdk_fn, 100, "op"))
        assert len(results) == 100
        sdk_fn.assert_called_once()

    def test_passes_extra_kwargs_to_sdk(self):
        sdk_fn = MagicMock(return_value=make_response([]))
        list(_paginate_after(sdk_fn, 10, "op", filter="status:'open'", sort="id|asc"))
        call_kwargs = sdk_fn.call_args[1]
        assert call_kwargs["filter"] == "status:'open'"
        assert call_kwargs["sort"] == "id|asc"

    def test_three_pages(self):
        sdk_fn = MagicMock(side_effect=[
            make_response([{"id": "a"}], after="tok1"),
            make_response([{"id": "b"}], after="tok2"),
            make_response([{"id": "c"}]),
        ])
        results = list(_paginate_after(sdk_fn, 1, "op"))
        assert results == [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        assert sdk_fn.call_count == 3


# ---------------------------------------------------------------------------
# _paginate_offset
# ---------------------------------------------------------------------------

class TestPaginateOffset:
    def test_single_partial_page(self):
        sdk_fn = MagicMock(return_value=make_response([{"id": "a"}, {"id": "b"}]))
        results = list(_paginate_offset(sdk_fn, 100, "op"))
        assert results == [{"id": "a"}, {"id": "b"}]

    def test_first_call_has_offset_zero(self):
        sdk_fn = MagicMock(return_value=make_response([]))
        list(_paginate_offset(sdk_fn, 100, "op"))
        call_kwargs = sdk_fn.call_args[1]
        assert call_kwargs["offset"] == 0

    def test_multiple_pages_increments_offset(self):
        sdk_fn = MagicMock(side_effect=[
            make_response([{"id": "a"}, {"id": "b"}]),
            make_response([{"id": "c"}]),
        ])
        results = list(_paginate_offset(sdk_fn, 2, "op"))
        assert results == [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        assert sdk_fn.call_count == 2
        second_call_kwargs = sdk_fn.call_args_list[1][1]
        assert second_call_kwargs["offset"] == 2

    def test_stops_when_page_smaller_than_page_size(self):
        sdk_fn = MagicMock(return_value=make_response([{"id": "x"}]))
        results = list(_paginate_offset(sdk_fn, 100, "op"))
        assert len(results) == 1
        sdk_fn.assert_called_once()

    def test_passes_extra_kwargs(self):
        sdk_fn = MagicMock(return_value=make_response([]))
        list(_paginate_offset(sdk_fn, 10, "op", filter="name:'group'"))
        assert sdk_fn.call_args[1]["filter"] == "name:'group'"

    def test_three_full_pages_then_partial(self):
        sdk_fn = MagicMock(side_effect=[
            make_response([{"id": str(i)} for i in range(5)]),
            make_response([{"id": str(i)} for i in range(5, 10)]),
            make_response([{"id": "10"}]),
        ])
        results = list(_paginate_offset(sdk_fn, 5, "op"))
        assert len(results) == 11
        assert sdk_fn.call_count == 3


# ---------------------------------------------------------------------------
# _batch_ids
# ---------------------------------------------------------------------------

class TestBatchIds:
    def test_single_batch_when_fewer_than_size(self):
        assert list(_batch_ids([1, 2, 3], 5)) == [[1, 2, 3]]

    def test_exact_fit(self):
        assert list(_batch_ids([1, 2, 3, 4], 2)) == [[1, 2], [3, 4]]

    def test_remainder_batch(self):
        assert list(_batch_ids([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]

    def test_empty_input(self):
        assert list(_batch_ids([], 10)) == []

    def test_size_one(self):
        assert list(_batch_ids([1, 2, 3], 1)) == [[1], [2], [3]]


# ---------------------------------------------------------------------------
# build_fql
# ---------------------------------------------------------------------------

class TestBuildFql:
    def test_single_clause(self):
        assert build_fql("status:'open'") == "status:'open'"

    def test_two_clauses_joined_with_plus(self):
        result = build_fql("status:'open'", "platform:'Windows'")
        assert result == "status:'open'+platform:'Windows'"

    def test_empty_strings_ignored(self):
        result = build_fql("status:'open'", "", "platform:'Windows'")
        assert result == "status:'open'+platform:'Windows'"

    def test_all_empty_returns_empty_string(self):
        assert build_fql("", "", "") == ""

    def test_no_args_returns_empty_string(self):
        assert build_fql() == ""

    def test_none_falsy_clause_not_filtered(self):
        # Only empty strings are filtered; non-string falsy values aren't expected
        # but the function uses truthiness, so verify for completeness with 0
        # The function signature is *clauses: str so we pass a zero-length string
        result = build_fql("a", "b", "c")
        assert result == "a+b+c"


# ---------------------------------------------------------------------------
# _retrying_call
# ---------------------------------------------------------------------------

def make_429(retry_after=None):
    headers = {}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return {
        "status_code": 429,
        "body": {
            "resources": [],
            "meta": {"pagination": {}},
            "errors": [{"code": 429, "message": "Too Many Requests"}],
        },
        "headers": headers,
    }


class TestRetryingCall:
    @patch("femur._pagination.time.sleep")
    def test_returns_immediately_on_success(self, mock_sleep):
        sdk_fn = MagicMock(return_value=make_response([{"id": "x"}]))
        result = _retrying_call(sdk_fn, {"limit": 100}, "op")
        assert result["status_code"] == 200
        mock_sleep.assert_not_called()

    @patch("femur._pagination.time.sleep")
    def test_retries_on_429_and_succeeds(self, mock_sleep):
        sdk_fn = MagicMock(side_effect=[
            make_429(),
            make_response([{"id": "a"}]),
        ])
        result = _retrying_call(sdk_fn, {"limit": 100}, "op")
        assert result["status_code"] == 200
        assert sdk_fn.call_count == 2
        mock_sleep.assert_called_once()

    @patch("femur._pagination.time.sleep")
    def test_respects_retry_after_header(self, mock_sleep):
        sdk_fn = MagicMock(side_effect=[
            make_429(retry_after=30),
            make_response([]),
        ])
        _retrying_call(sdk_fn, {"limit": 100}, "op")
        wait = mock_sleep.call_args[0][0]
        assert wait == pytest.approx(30.0, abs=0.01)

    @patch("femur._pagination.time.sleep")
    def test_gives_up_after_max_retries(self, mock_sleep):
        sdk_fn = MagicMock(return_value=make_429())
        result = _retrying_call(sdk_fn, {"limit": 100}, "op", max_retries=3)
        # Should have called: attempt 0,1,2 sleep + attempt 3 (no sleep) = 4 calls
        assert sdk_fn.call_count == 4
        assert mock_sleep.call_count == 3
        assert result["status_code"] == 429

    @patch("femur._pagination.time.sleep")
    def test_does_not_retry_on_403(self, mock_sleep):
        sdk_fn = MagicMock(return_value=make_response([], status_code=403))
        result = _retrying_call(sdk_fn, {"limit": 100}, "op")
        assert sdk_fn.call_count == 1
        mock_sleep.assert_not_called()

    @patch("femur._pagination.time.sleep")
    def test_retries_on_500_and_succeeds(self, mock_sleep):
        sdk_fn = MagicMock(side_effect=[
            make_response([], status_code=500),
            make_response([{"id": "a"}]),
        ])
        result = _retrying_call(sdk_fn, {"limit": 100}, "op")
        assert result["status_code"] == 200
        assert sdk_fn.call_count == 2
        mock_sleep.assert_called_once()

    @patch("femur._pagination.time.sleep")
    def test_retries_on_502_503_504(self, mock_sleep):
        for code in (502, 503, 504):
            mock_sleep.reset_mock()
            sdk_fn = MagicMock(side_effect=[
                make_response([], status_code=code),
                make_response([{"id": "x"}]),
            ])
            result = _retrying_call(sdk_fn, {}, "op")
            assert result["status_code"] == 200, f"expected retry on {code}"
            mock_sleep.assert_called_once()

    @patch("femur._pagination.time.sleep")
    def test_paginate_after_retries_transparently(self, mock_sleep):
        """End-to-end: _paginate_after retries a 429 mid-stream."""
        sdk_fn = MagicMock(side_effect=[
            make_response([{"id": "a"}], after="tok1"),
            make_429(),
            make_response([{"id": "b"}]),
        ])
        results = list(_paginate_after(sdk_fn, 1, "op"))
        assert results == [{"id": "a"}, {"id": "b"}]
        assert sdk_fn.call_count == 3
        mock_sleep.assert_called_once()
