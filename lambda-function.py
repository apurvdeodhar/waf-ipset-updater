import ipaddress
import logging
import os

import boto3

s3 = boto3.client("s3")
waf = boto3.client("wafv2")
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# These are used as placeholders for now but you can adjust them if required
IPSET_NAME = "Blacklisted-IPs"
IPSET_SCOPE = "REGIONAL"
IPSET_REGION = os.environ.get("AWS_REGION", "us-east-1")
MAX_IPS = 10000


def lambda_handler(event, context):
    try:
        # Here we're parsing S3 Event
        bucket = event["Records"][0]["s3"]["bucket"]["name"]
        key = event["Records"][0]["s3"]["object"]["key"]
        logger.info(f"Processing file from {bucket}/{key}")

        # Then download the file
        response = s3.get_object(Bucket=bucket, Key=key)
        content = response["Body"].read().decode("utf-8")
        lines = content.strip().splitlines()

        # For now we opnly take last 10,000 lines, but you can adjust this according to your needs
        logger.info(f"Total lines in blacklist file: {len(lines)}")
        if len(lines) > MAX_IPS:
            logger.warning(
                f"More than {MAX_IPS} lines found, truncating to last {MAX_IPS} lines."
            )
        recent_ips = lines[-MAX_IPS:]

        # This is validating and avoids deduplicate
        valid_cidrs = []
        seen = set()
        for line in recent_ips:
            line = line.strip()
            try:
                cidr = ipaddress.ip_network(line)
                cidr_str = str(cidr)
                if cidr_str not in seen:
                    valid_cidrs.append(cidr_str)
                    seen.add(cidr_str)
            except ValueError:
                logger.warning(f"Invalid CIDR skipped: {line}")
                continue

        logger.info(f"Valid CIDRs to apply: {len(valid_cidrs)}")

        ipset_id, lock_token = get_ipset_id_and_token(IPSET_NAME, IPSET_SCOPE)
        if not ipset_id:
            logger.error("Could not find IPSet")
            logger.error(f"IPSet Name: {IPSET_NAME}, Scope: {IPSET_SCOPE}")
            return

        # Finally here we update the IPSet with new list
        waf.update_ip_set(
            Name=IPSET_NAME,
            Scope=IPSET_SCOPE,
            Id=ipset_id,
            LockToken=lock_token,
            Addresses=valid_cidrs,
        )

        logger.info(f"WAF IPSet updated successfully with {len(valid_cidrs)} entries.")

    except Exception as e:
        logger.exception("Error processing blacklist update.")
        raise e


def get_ipset_id_and_token(name, scope):
    """Find IPSet by name and return its ID and LockToken (handling pagination)"""
    paginator = waf.get_paginator("list_ip_sets")
    for page in paginator.paginate(Scope=scope):
        for ipset in page["IPSets"]:
            if ipset["Name"] == name:
                ipset_id = ipset["Id"]
                ipset_details = waf.get_ip_set(Name=name, Scope=scope, Id=ipset_id)
                return ipset_id, ipset_details["LockToken"]
    return None, None
