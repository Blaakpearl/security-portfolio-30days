"""
Day 24 — CloudTrail Hunter
NovaCrest Capital Group | Cloud Infrastructure Threat Hunt

PURPOSE: Analyzes AWS CloudTrail events to detect attacker activity across
         six hypotheses: enumeration, IAM backdoor creation, Secrets Manager
         access, S3 data exfiltration, EC2 abuse, and CloudTrail/GuardDuty
         tampering. Simulates a full 7-day post-compromise cloud hunt.

DATA SOURCE: AWS CloudTrail JSON logs (Management + Data events)
HUNT WINDOW: 2026-06-14 00:00 UTC → 2026-06-21 00:00 UTC
ATTACKER IP: 198.51.100.99

Usage:
    python cloudtrail_hunter.py --demo --verbose
    python cloudtrail_hunter.py --log-file /tmp/all_cloudtrail_events.json
    python cloudtrail_hunter.py --demo --hypothesis H3
    python cloudtrail_hunter.py --demo --json
"""

import argparse
import datetime
import json
import logging
from collections import defaultdict
from typing import Dict, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("cloudtrail_hunter")

ATTACKER_IP = "198.51.100.99"
ATTACKER_ACCOUNT = "987654321099"   # Attacker's AWS account (for cross-account calls)

# ── Simulated CloudTrail Events (Demo Mode) ────────────────────────────
SIMULATED_EVENTS = [

    # ─── H1: Enumeration ──────────────────────────────────────────────
    {"eventTime": "2026-06-16T09:00:11Z", "eventSource": "sts.amazonaws.com",
     "eventName": "GetCallerIdentity", "sourceIPAddress": ATTACKER_IP,
     "userAgent": "aws-cli/2.15.0",
     "userIdentity": {"type": "IAMUser", "userName": "trading-api-deploy"},
     "note": "Attacker verifies credential validity — first action"},

    {"eventTime": "2026-06-16T09:01:03Z", "eventSource": "iam.amazonaws.com",
     "eventName": "ListUsers", "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole", "sessionContext": {"sessionIssuer": {"userName": "novacrest-admin-role"}}},
     "note": "IAM user enumeration post AssumeRole"},

    {"eventTime": "2026-06-16T09:01:18Z", "eventSource": "iam.amazonaws.com",
     "eventName": "ListRoles", "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "IAM role enumeration — looking for other assumable roles"},

    {"eventTime": "2026-06-16T09:01:45Z", "eventSource": "s3.amazonaws.com",
     "eventName": "ListBuckets", "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "S3 bucket enumeration — inventory of all buckets"},

    {"eventTime": "2026-06-16T09:02:10Z", "eventSource": "ec2.amazonaws.com",
     "eventName": "DescribeInstances", "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "EC2 instance enumeration — map compute environment"},

    {"eventTime": "2026-06-16T09:02:33Z", "eventSource": "secretsmanager.amazonaws.com",
     "eventName": "ListSecrets", "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "Secrets Manager listing — identify high-value secrets"},

    {"eventTime": "2026-06-16T09:02:58Z", "eventSource": "lambda.amazonaws.com",
     "eventName": "ListFunctions", "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "Lambda enumeration — trading signal processing functions"},

    {"eventTime": "2026-06-16T09:03:20Z", "eventSource": "sagemaker.amazonaws.com",
     "eventName": "ListModels", "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "SageMaker model enumeration — ML trading models"},

    # ─── H2: IAM Backdoor ─────────────────────────────────────────────
    {"eventTime": "2026-06-16T09:15:44Z", "eventSource": "iam.amazonaws.com",
     "eventName": "CreateUser",
     "requestParameters": {"userName": "svc-monitoring-ops"},
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "BACKDOOR: Created hidden IAM user 'svc-monitoring-ops'"},

    {"eventTime": "2026-06-16T09:16:02Z", "eventSource": "iam.amazonaws.com",
     "eventName": "AttachUserPolicy",
     "requestParameters": {
         "userName": "svc-monitoring-ops",
         "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
     },
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "BACKDOOR: Attached AdministratorAccess to backdoor user"},

    {"eventTime": "2026-06-16T09:16:28Z", "eventSource": "iam.amazonaws.com",
     "eventName": "CreateAccessKey",
     "requestParameters": {"userName": "svc-monitoring-ops"},
     "responseElements": {
         "accessKey": {
             "accessKeyId": "AKIAIOSFODNN7BACKDOOR",
             "status": "Active",
             "userName": "svc-monitoring-ops"
         }
     },
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "BACKDOOR: Created persistent access key for backdoor user"},

    {"eventTime": "2026-06-16T09:18:11Z", "eventSource": "iam.amazonaws.com",
     "eventName": "CreateRole",
     "requestParameters": {
         "roleName": "CrossAccountReadRole",
         "assumeRolePolicyDocument": json.dumps({
             "Version": "2012-10-17",
             "Statement": [{
                 "Effect": "Allow",
                 "Principal": {"AWS": f"arn:aws:iam::{ATTACKER_ACCOUNT}:root"},
                 "Action": "sts:AssumeRole"
             }]
         })
     },
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "BACKDOOR: Created cross-account role trusting attacker AWS account"},

    # ─── H3: Secrets Manager Access ───────────────────────────────────
    {"eventTime": "2026-06-16T09:10:05Z", "eventSource": "secretsmanager.amazonaws.com",
     "eventName": "GetSecretValue",
     "requestParameters": {"secretId": "novacrest/bloomberg/api-key"},
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "Bloomberg API key harvested from Secrets Manager"},

    {"eventTime": "2026-06-16T09:10:22Z", "eventSource": "secretsmanager.amazonaws.com",
     "eventName": "GetSecretValue",
     "requestParameters": {"secretId": "novacrest/rds/trading-db-password"},
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "RDS trading database password harvested"},

    {"eventTime": "2026-06-16T09:10:38Z", "eventSource": "secretsmanager.amazonaws.com",
     "eventName": "GetSecretValue",
     "requestParameters": {"secretId": "novacrest/trading/execution-api-key"},
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "Trading execution API key harvested — direct market access risk"},

    # ─── H4: S3 Data Exfiltration ─────────────────────────────────────
    {"eventTime": "2026-06-16T09:25:01Z", "eventSource": "s3.amazonaws.com",
     "eventName": "GetObject",
     "requestParameters": {
         "bucketName": "novacrest-trading-data",
         "key": "client-data/account-balances-2026-06.csv"
     },
     "additionalEventData": {"bytesTransferredOut": 4194304},
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "Client account balances downloaded (4 MB) — SEC Reg S-P trigger"},

    {"eventTime": "2026-06-16T09:27:14Z", "eventSource": "s3.amazonaws.com",
     "eventName": "GetObject",
     "requestParameters": {
         "bucketName": "novacrest-trading-data",
         "key": "algorithms/eod-positions-2026-06-15.parquet"
     },
     "additionalEventData": {"bytesTransferredOut": 18874368},
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "EOD trading positions (18 MB) — live position data exposure"},

    {"eventTime": "2026-06-16T09:29:45Z", "eventSource": "s3.amazonaws.com",
     "eventName": "GetObject",
     "requestParameters": {
         "bucketName": "novacrest-ml-models",
         "key": "sagemaker/trained/trading-signal-v3.tar.gz"
     },
     "additionalEventData": {"bytesTransferredOut": 62914560},
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "SageMaker ML trading model (60 MB) — core IP"},

    # ─── H5: EC2 Crypto Mining Attempt ────────────────────────────────
    {"eventTime": "2026-06-16T10:05:33Z", "eventSource": "ec2.amazonaws.com",
     "eventName": "RunInstances",
     "requestParameters": {
         "instanceType": "p3.8xlarge",   # GPU instance — mining optimized
         "imageId": "ami-0abcdef1234567890",
         "minCount": 3,
         "maxCount": 3,
         "keyName": "attacker-key",
         "tagSpecifications": [{"resourceType": "instance",
                                "tags": [{"key": "Name",
                                          "value": "monitoring-node"}]}]
     },
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "CRITICAL: 3× p3.8xlarge GPU instances launched — crypto mining pattern (GPU + 'monitoring-node' label)"},

    # ─── H6: CloudTrail Tampering ─────────────────────────────────────
    {"eventTime": "2026-06-16T09:05:02Z", "eventSource": "cloudtrail.amazonaws.com",
     "eventName": "StopLogging",
     "requestParameters": {
         "name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/novacrest-main-trail"
     },
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "CRITICAL: Attacker stopped CloudTrail logging — evidence destruction attempt"},

    {"eventTime": "2026-06-16T09:05:18Z", "eventSource": "guardduty.amazonaws.com",
     "eventName": "UpdateDetector",
     "requestParameters": {
         "detectorId": "abc123def456",
         "enable": False,
         "findingPublishingFrequency": "SIX_HOURS"
     },
     "sourceIPAddress": ATTACKER_IP,
     "userIdentity": {"type": "AssumedRole"},
     "note": "CRITICAL: GuardDuty detector disabled — blind detection during attack"},
]

# Hypothesis definitions
HYPOTHESES = {
    "H1": {"name": "Cloud Enumeration", "technique": "T1526", "severity": "Medium",
           "event_names": {"GetCallerIdentity","ListUsers","ListRoles","ListBuckets",
                           "DescribeInstances","ListSecrets","ListFunctions","ListModels",
                           "DescribeVpcs","ListPolicies","DescribeSecurityGroups"}},
    "H2": {"name": "IAM Backdoor Creation", "technique": "T1136.003", "severity": "Critical",
           "event_names": {"CreateUser","AttachUserPolicy","CreateAccessKey","CreateRole",
                           "PutUserPolicy","PutRolePolicy","AddUserToGroup"}},
    "H3": {"name": "Secrets Manager Access", "technique": "T1555.006", "severity": "Critical",
           "event_names": {"GetSecretValue"}},
    "H4": {"name": "S3 Data Exfiltration", "technique": "T1530", "severity": "Critical",
           "event_names": {"GetObject","CopyObject","GetObjectAcl"}},
    "H5": {"name": "EC2 Compute Abuse", "technique": "T1578", "severity": "High",
           "event_names": {"RunInstances","StartInstances","ModifyInstanceAttribute"}},
    "H6": {"name": "CloudTrail/GuardDuty Tampering", "technique": "T1562.008", "severity": "Critical",
           "event_names": {"StopLogging","DeleteTrail","UpdateDetector","DisassociateFromMasterAccount"}},
}


def hunt_hypothesis(hyp_id: str, hyp: Dict, events: List[Dict],
                    verbose: bool) -> Dict:
    findings = []
    for event in events:
        if event.get("eventName") in hyp["event_names"]:
            src_ip = event.get("sourceIPAddress", "")
            # For cloud hunt, flag both attacker IP and any external non-AWS IP
            is_suspicious = (src_ip == ATTACKER_IP or
                             not src_ip.startswith(("10.", "172.16.", "192.168.",
                                                     "AWS", "Internal")))
            if is_suspicious:
                finding = {
                    "hypothesis": hyp_id,
                    "technique": hyp["technique"],
                    "timestamp": event["eventTime"],
                    "event_name": event["eventName"],
                    "event_source": event.get("eventSource", ""),
                    "source_ip": src_ip,
                    "request_params": event.get("requestParameters", {}),
                    "evidence": event.get("note", event["eventName"]),
                    "severity": hyp["severity"],
                }
                findings.append(finding)
                if verbose:
                    sev = hyp["severity"]
                    icon = ("🔴" if sev == "Critical" else
                            "🟠" if sev == "High" else "🟡")
                    log.info(f"  {icon} [{sev}] {event['eventTime']} "
                             f"{event['eventName']}: {event.get('note','')[:65]}")

    return {
        "hypothesis": hyp_id,
        "name": hyp["name"],
        "technique": hyp["technique"],
        "severity": hyp["severity"],
        "confirmed": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
        "verdict": "CONFIRMED" if findings else "NOT FOUND",
    }


def compute_total_bytes_exfiltrated(events: List[Dict]) -> int:
    total = 0
    for e in events:
        if e.get("eventName") == "GetObject":
            total += e.get("additionalEventData", {}).get("bytesTransferredOut", 0)
    return total


def emit_hunt_report(results: List[Dict], total_bytes: int) -> None:
    confirmed = [r for r in results if r["confirmed"]]
    print("\n" + "=" * 70)
    print("  CLOUD INFRASTRUCTURE HUNT REPORT — Day 24")
    print("  NovaCrest Capital Group | AWS Account 123456789012")
    print("=" * 70 + "\n")
    print(f"  Hunt window: 2026-06-14 00:00 → 2026-06-21 00:00 UTC")
    print(f"  Attacker IP: {ATTACKER_IP}")
    print(f"  Hypotheses:  {len(results)} tested | {len(confirmed)} confirmed")
    if total_bytes:
        print(f"  S3 bytes exfiltrated via CloudTrail: {total_bytes:,} "
              f"({round(total_bytes/1_048_576,1)} MB)")
    print()

    print(f"  {'HYP':<4} {'NAME':<30} {'TECHNIQUE':<12} {'SEV':<10} {'VERDICT'}")
    print("  " + "─" * 65)
    for r in results:
        icon = "✅" if r["confirmed"] else "⬜"
        print(f"  {icon} {r['hypothesis']:<3} {r['name']:<30} "
              f"{r['technique']:<12} {r['severity']:<10} {r['verdict']}")
    print()

    if confirmed:
        print("  CONFIRMED FINDINGS SUMMARY:")
        print("  " + "─" * 55)
        for r in confirmed:
            print(f"  [{r['hypothesis']}] {r['name']}: {r['finding_count']} events")
            for f in r["findings"][:2]:  # show first 2 findings per hypothesis
                print(f"    → {f['timestamp']} {f['event_name']}: {f['evidence'][:55]}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Day 24 CloudTrail Hunter")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--hypothesis", choices=list(HYPOTHESES.keys()))
    parser.add_argument("--log-file", help="Path to CloudTrail JSON")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--output", default="/tmp/cloud_hunt_results.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 24 — CloudTrail Hunter")
    log.info(" NovaCrest Capital Group | Cloud Infrastructure Hunt")
    log.info("=" * 70)
    log.info(f" Attacker IP: {ATTACKER_IP} | Window: 2026-06-14 → 2026-06-21")
    log.info("")

    events = SIMULATED_EVENTS

    hyps_to_run = (
        {args.hypothesis: HYPOTHESES[args.hypothesis]}
        if args.hypothesis else HYPOTHESES
    )

    results = []
    for hyp_id, hyp in hyps_to_run.items():
        log.info(f"[{hyp_id}] Hunting: {hyp['name']} ({hyp['technique']})")
        result = hunt_hypothesis(hyp_id, hyp, events, args.verbose)
        results.append(result)
        log.info(f"  → {result['verdict']} ({result['finding_count']} findings)")
        log.info("")

    total_bytes = compute_total_bytes_exfiltrated(events)
    emit_hunt_report(results, total_bytes)

    output = {
        "hunt": "Cloud Infrastructure Hunt",
        "attacker_ip": ATTACKER_IP,
        "window": "2026-06-14 → 2026-06-21",
        "total_bytes_exfiltrated": total_bytes,
        "results": results,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"Results written: {args.output}")

    if args.json:
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
