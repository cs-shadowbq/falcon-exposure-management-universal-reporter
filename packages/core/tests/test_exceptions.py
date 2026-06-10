import pytest

from femur._exceptions import FalconAPIError


class TestFalconAPIError:
    def test_is_exception_subclass(self):
        err = FalconAPIError("op", 403, [])
        assert isinstance(err, Exception)

    def test_stores_attributes(self):
        errors = [{"code": 403, "message": "Access denied"}]
        err = FalconAPIError("my_op", 403, errors)
        assert err.operation == "my_op"
        assert err.status_code == 403
        assert err.errors == errors

    def test_str_includes_operation(self):
        err = FalconAPIError("my_op", 403, [{"code": 403, "message": "Access denied"}])
        assert "my_op" in str(err)

    def test_str_includes_error_message(self):
        err = FalconAPIError("my_op", 403, [{"code": 403, "message": "Access denied"}])
        assert "Access denied" in str(err)

    def test_empty_errors_shows_http_status_code(self):
        err = FalconAPIError("my_op", 404, [])
        assert "404" in str(err)
        assert "my_op" in str(err)

    def test_multiple_errors_joined(self):
        errors = [
            {"code": 400, "message": "Bad filter"},
            {"code": 400, "message": "Missing field"},
        ]
        err = FalconAPIError("op", 400, errors)
        assert "Bad filter" in str(err)
        assert "Missing field" in str(err)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(FalconAPIError) as exc_info:
            raise FalconAPIError("op", 500, [{"code": 500, "message": "Server error"}])
        assert exc_info.value.status_code == 500
