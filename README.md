# WAF IPSet Updater


#### High-Level Flow

1. Lambda is triggered via S3 event notification.
2. Reads the contents of `blacklist.txt` (one CIDR per line).
3. Extracts the last 10,000 valid IP addresses.
4. Deduplicates and validates entries using Python’s `ipaddress` module.
5. Updates the existing WAF IPSet via `update_ip_set`.

#### Key Implementation Points

- **CIDR Validation**: Ensures only valid IP ranges are applied to WAF.
- **Deduplication**: Avoids redundant entries in the IPSet.
- **Pagination**: Handles WAF list and get operations cleanly with pagination and LockToken support.
- **Logging**: Logs key events and skipped invalid entries.
- **No External Dependencies**: Runs using standard Python 3.11 libraries (`boto3`, `ipaddress`).

#### Pre-requisites
- Install and configure [pre-commit](https://github.com/pre-commit/pre-commit)
- Configure your AWS credentials `(~/.aws/credentials or env vars)`.
- Upload a `blacklist.txt` to a test S3 bucket.
- Use the sample test event structure `(test_lambda.py)` for simulations.


#### Local Testing

Test the Lambda locally by running:

```bash
python lambda_function.py
```

#### Deployment

As no additional dependencies are needed. The deployment can be done by:
```bash
zip waf-lambda.zip lambda_function.py
```
And then simply upload `waf-lambda.zip` to AWS Console or use AWS CLI.


#### Testing

Use included `test_lambda.py` unit tests using `unittest.mock` to simulate S3 and WAFv2 behavior.
