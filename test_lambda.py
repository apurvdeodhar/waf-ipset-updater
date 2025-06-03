import io
from unittest.mock import patch

import lambda_function

# To simulate S3 trigger
SAMPLE_EVENT = {
    "Records": [
        {"s3": {"bucket": {"name": "test-bucket"}, "object": {"key": "blacklist.txt"}}}
    ]
}

# Sample blacklist file content I just used ones from tech challenge pdf
BLACKLIST_CONTENT = "\n".join(
    [
        "203.0.113.45/32",
        "198.51.100.0/28",
        "invalid-entry",
        "177.51.100.0/28",
        "192.51.100.0/23",
    ]
)


@patch("lambda_function.s3")
@patch("lambda_function.waf")
def test_lambda_handler_success(mock_waf, mock_s3):
    mock_s3.get_object.return_value = {
        "Body": io.BytesIO(BLACKLIST_CONTENT.encode("utf-8"))
    }

    mock_waf.get_paginator.return_value.paginate.return_value = [
        {"IPSets": [{"Name": "Blacklisted-IPs", "Id": "abc123"}]}
    ]
    mock_waf.get_ip_set.return_value = {
        "LockToken": "mock-token",
        "IPSet": {"Addresses": []},
    }

    lambda_function.lambda_handler(SAMPLE_EVENT, None)

    # Check WAF update was called with filtered IPs
    args, kwargs = mock_waf.update_ip_set.call_args
    assert "203.0.113.45/32" in kwargs["Addresses"]
    assert "198.51.100.0/28" in kwargs["Addresses"]
    assert "177.51.100.0/28" in kwargs["Addresses"]
    assert "invalid-entry" not in kwargs["Addresses"]
    assert "192.51.100.0/23" not in kwargs["Addresses"]
