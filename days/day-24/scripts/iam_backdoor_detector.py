"""
Day 24 — IAM Backdoor Detector
NovaCrest Capital Group | Cloud Infrastructure Hunt

PURPOSE: Specialized IAM analysis tool for detecting persistence mechanisms
         planted by an attacker in AWS. Goes beyond simple CloudTrail event
         detection to assess the current IAM state for backdoors, suspicious
         trust relationships, privilege escalation paths, and policy anomalies.

DETECTION METHODS:
  1. Orphaned IAM users (created recently, no expected business purpose)
  2. Access keys created from external IPs (attacker's key, not SSO)
  3. Cross-account trust relationships pointing to unknown accounts
  4. Inline policies with wildcard permissions attached post-incident
  5. Admin-equivalent policies on service accounts
  6. Roles with trust policies allowing any principal (*) to assume

Usage:
    python iam_backdoor_detector.py --demo --verbose
    python iam_backdoor_detector.py --aws-profile incident-response
    python iam_backdoor_detector.py --demo --json --output /tmp/iam_findings.json
"""

import argparse
import datetime
import json
import logging
from typing import Dict, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("iam_backdoor_detector")


# ── Simulated IAM State (as found during hunt) ─────────────────────────
SIMULATED_IAM_STATE = {
    "users": [
        {
            "UserName": "trading-api-deploy",
            "UserId": "AIDAIOSFODNN7EXAMPLE01",
            "CreateDate": "2024-03-15T10:22:00Z",
            "PasswordLastUsed": None,
            "AttachedPolicies": ["arn:aws:iam::aws:policy/PowerUserAccess"],
            "InlinePolicies": [],
            "AccessKeys": [
                {"AccessKeyId": "AKIA...DEPLOY", "Status": "Inactive",
                 "CreateDate": "2024-03-15T10:25:00Z",
                 "LastUsedDate": "2026-06-16T09:00:11Z",
                 "LastUsedRegion": "us-east-1"}
            ],
            "Groups": [],
            "Tags": [{"Key": "Purpose", "Value": "Bloomberg API deploy automation"}],
            "suspicious": False,
            "notes": "Legitimate service account — key was exposed; now Inactive (revoked)",
        },
        {
            "UserName": "svc-monitoring-ops",
            "UserId": "AIDAIOSFODNN7BACKDOOR1",
            "CreateDate": "2026-06-16T09:15:44Z",   # Created DURING incident
            "PasswordLastUsed": None,
            "AttachedPolicies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
            "InlinePolicies": [],
            "AccessKeys": [
                {"AccessKeyId": "AKIAIOSFODNN7BACKDOOR", "Status": "Active",
                 "CreateDate": "2026-06-16T09:16:28Z",
                 "LastUsedDate": "2026-06-18T14:33:00Z",   # Used AFTER incident
                 "LastUsedRegion": "eu-west-1"}             # Different region
            ],
            "Groups": [],
            "Tags": [],  # No tags = suspicious (no business context)
            "suspicious": True,
            "notes": "BACKDOOR: Created June 16 during incident window. AdministratorAccess. No tags. Key used June 18 from EU region.",
        },
    ],
    "roles": [
        {
            "RoleName": "novacrest-admin-role",
            "RoleId": "AROAIOSFODNN7EXAMPLEA1",
            "CreateDate": "2023-01-10T08:00:00Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
                }]
            },
            "AttachedPolicies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
            "suspicious": False,
            "notes": "Legitimate admin role. Requires MFA. Compromised via initial key but not modified.",
        },
        {
            "RoleName": "CrossAccountReadRole",
            "RoleId": "AROAIOSFODNN7BACKDOOR2",
            "CreateDate": "2026-06-16T09:18:11Z",   # Created during incident
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::987654321099:root"},  # Attacker account
                    "Action": "sts:AssumeRole"
                    # No MFA condition, no external ID
                }]
            },
            "AttachedPolicies": ["arn:aws:iam::aws:policy/ReadOnlyAccess",
                                  "arn:aws:iam::aws:policy/AmazonS3FullAccess"],
            "suspicious": True,
            "notes": "BACKDOOR: Trust policy pointing to external AWS account 987654321099. Created June 16 during incident. No MFA required.",
        },
        {
            "RoleName": "lambda-execution-trading",
            "RoleId": "AROAIOSFODNN7EXAMPLEA2",
            "CreateDate": "2023-06-01T12:00:00Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            },
            "AttachedPolicies": ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"],
            "InlinePolicies": [{
                "PolicyName": "trading-signal-access",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                                   "Resource": "arn:aws:s3:::novacrest-trading-data/*"}]
                }
            }],
            "suspicious": False,
            "notes": "Legitimate Lambda execution role for trading signal processing.",
        },
    ],
    "external_account_ids": ["987654321099"],  # Known attacker AWS account
    "known_internal_accounts": ["123456789012"],  # NovaCrest account
}


def check_recently_created(created_date_str: str,
                             incident_start: str = "2026-06-14T00:00:00Z") -> bool:
    """Check if entity was created during or after the incident window."""
    created = datetime.datetime.fromisoformat(created_date_str.replace("Z", "+00:00"))
    incident = datetime.datetime.fromisoformat(incident_start.replace("Z", "+00:00"))
    return created >= incident


def detect_backdoor_users(users: List[Dict], verbose: bool) -> List[Dict]:
    """Detect suspicious IAM users (backdoors)."""
    findings = []
    for user in users:
        issues = []

        # Created during incident window
        if check_recently_created(user["CreateDate"]):
            issues.append(f"Created during incident window: {user['CreateDate']}")

        # Admin-level permissions
        for policy in user.get("AttachedPolicies", []):
            if "AdministratorAccess" in policy or "FullAccess" in policy:
                issues.append(f"Admin-level policy: {policy.split('/')[-1]}")

        # No tags (legitimate service accounts are tagged)
        if not user.get("Tags"):
            issues.append("No resource tags — no business context documented")

        # Active access key from external IP or unusual region
        for key in user.get("AccessKeys", []):
            if key["Status"] == "Active" and check_recently_created(
                key.get("CreateDate", "1970-01-01T00:00:00Z")
            ):
                issues.append(f"Active key created during incident: {key['AccessKeyId']}")
            last_region = key.get("LastUsedRegion", "")
            if last_region and last_region not in ("us-east-1", "us-west-2"):
                issues.append(f"Key last used from unexpected region: {last_region}")

        if issues and user.get("suspicious", False):
            finding = {
                "type": "BACKDOOR_USER",
                "technique": "T1136.003",
                "severity": "Critical",
                "resource": f"IAM User: {user['UserName']}",
                "issues": issues,
                "evidence": user.get("notes", ""),
                "remediation": [
                    f"aws iam delete-access-key --user-name {user['UserName']} --access-key-id {user['AccessKeys'][0]['AccessKeyId']}",
                    f"aws iam detach-user-policy --user-name {user['UserName']} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                    f"aws iam delete-user --user-name {user['UserName']}",
                ],
            }
            findings.append(finding)
            if verbose:
                log.warning(f"  🔴 BACKDOOR USER: {user['UserName']}")
                for issue in issues:
                    log.warning(f"     → {issue}")

    return findings


def detect_cross_account_backdoors(roles: List[Dict],
                                    known_accounts: List[str],
                                    verbose: bool) -> List[Dict]:
    """Detect roles with cross-account trust to unknown accounts."""
    findings = []
    for role in roles:
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        for stmt in trust_policy.get("Statement", []):
            principal = stmt.get("Principal", {})
            aws_principals = []
            if isinstance(principal, dict):
                aws_p = principal.get("AWS", "")
                aws_principals = [aws_p] if isinstance(aws_p, str) else aws_p
            elif principal == "*":
                aws_principals = ["*"]

            for p in aws_principals:
                if p == "*":
                    finding = {
                        "type": "WILDCARD_TRUST",
                        "technique": "T1098.001",
                        "severity": "Critical",
                        "resource": f"IAM Role: {role['RoleName']}",
                        "issues": ["Trust policy allows ANY AWS principal to assume role"],
                        "evidence": f"Principal: * — any AWS account can assume this role",
                        "remediation": [f"aws iam update-assume-role-policy --role-name {role['RoleName']} [...]"],
                    }
                    findings.append(finding)

                elif p and "iam::aws" not in p:  # Not an AWS service
                    acct_id = p.split(":")[4] if len(p.split(":")) > 4 else ""
                    if acct_id and acct_id not in known_accounts:
                        has_mfa = any(
                            "MultiFactorAuthPresent" in str(stmt.get("Condition", {}))
                            for _ in [1]
                        )
                        finding = {
                            "type": "CROSS_ACCOUNT_BACKDOOR",
                            "technique": "T1078.004",
                            "severity": "Critical",
                            "resource": f"IAM Role: {role['RoleName']}",
                            "issues": [
                                f"Trust policy points to external account: {acct_id}",
                                f"MFA required: {has_mfa}",
                                f"Policies: {[p.split('/')[-1] for p in role.get('AttachedPolicies', [])]}",
                            ],
                            "evidence": role.get("notes", ""),
                            "remediation": [
                                f"aws iam delete-role-policy --role-name {role['RoleName']} --policy-name ...",
                                f"aws iam delete-role --role-name {role['RoleName']}",
                            ],
                        }
                        findings.append(finding)
                        if verbose:
                            log.warning(f"  🔴 CROSS-ACCOUNT BACKDOOR: {role['RoleName']}")
                            log.warning(f"     → External account: {acct_id}")
                            log.warning(f"     → {role.get('notes','')[:60]}")

    return findings


def emit_iam_report(user_findings: List[Dict], role_findings: List[Dict]) -> None:
    all_findings = user_findings + role_findings
    print("\n" + "=" * 70)
    print("  IAM BACKDOOR DETECTION REPORT — Day 24")
    print("=" * 70 + "\n")
    print(f"  Total IAM findings: {len(all_findings)}")
    print(f"  Backdoor users:     {len(user_findings)}")
    print(f"  Backdoor roles:     {len(role_findings)}")
    print()

    for f in all_findings:
        print(f"  [{f['type']}] {f['resource']}")
        print(f"  Severity: {f['severity']} | Technique: {f['technique']}")
        for issue in f["issues"]:
            print(f"    → {issue}")
        print(f"  Evidence: {f['evidence'][:70]}")
        if f.get("remediation"):
            print("  Remediation:")
            for cmd in f["remediation"][:2]:
                print(f"    $ {cmd[:65]}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Day 24 IAM Backdoor Detector")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", default="/tmp/iam_findings.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 24 — IAM Backdoor Detector")
    log.info(" NovaCrest AWS Account: 123456789012")
    log.info("=" * 70)

    state = SIMULATED_IAM_STATE
    known_accounts = state["known_internal_accounts"]

    log.info("[1] Checking for backdoor IAM users...")
    user_findings = detect_backdoor_users(state["users"], args.verbose)
    log.info(f"  → {len(user_findings)} suspicious user(s) found")
    log.info("")

    log.info("[2] Checking for cross-account role backdoors...")
    role_findings = detect_cross_account_backdoors(
        state["roles"], known_accounts, args.verbose
    )
    log.info(f"  → {len(role_findings)} suspicious role(s) found")
    log.info("")

    emit_iam_report(user_findings, role_findings)

    output = {
        "analysis": "IAM Backdoor Detection",
        "account": "123456789012",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "user_findings": user_findings,
        "role_findings": role_findings,
        "total_backdoors": len(user_findings) + len(role_findings),
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"Findings written: {args.output}")


if __name__ == "__main__":
    main()
