"""
Day 23 — Mobile OSINT Profiler
NovaCrest Capital Group | Mobile OSINT

PURPOSE: Simulates a complete mobile identity footprinting pipeline:
         phone number OSINT, social account enumeration, breach exposure
         check, and MDM device compliance audit. Produces a unified mobile
         threat profile for the target subject and org-wide MDM gap report.

MODULES:
  1. Phone OSINT       — carrier, line type, registration
  2. Social Footprint  — platform presence, username variants
  3. Breach Exposure   — HIBP-style breach database check
  4. MDM Audit         — Jamf Pro device compliance (simulated)
  5. Cell Tower        — location history from tower records (simulated)

LEGAL NOTE: This script uses entirely simulated data for portfolio
            demonstration. Real phone OSINT and MDM audits require
            legal authorization. Cell tower data requires legal process.

Usage:
    python mobile_osint_profiler.py --demo --subject jhenderson --verbose
    python mobile_osint_profiler.py --mode phone --demo
    python mobile_osint_profiler.py --mode mdm-audit --demo
    python mobile_osint_profiler.py --mode all --demo --report
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
log = logging.getLogger("mobile_osint_profiler")


# ── Simulated Subject Profile ──────────────────────────────────────────
SUBJECT = {
    "name": "Jennifer Henderson",
    "alias": "j.henderson",
    "email_corporate": "jhenderson@novacrest.com",
    "email_personal": "jhenderson85@gmail.com",   # Found via breach data
    "phone_corporate": "+12125550134",
    "phone_personal": "+19175550287",
    "username_variants": [
        "jhenderson_nyc",
        "jhendersonfinance",
        "j.henderson.nyc",
        "jhenderson85",
    ],
    "employer": "NovaCrest Capital Group",
    "title": "Senior Financial Analyst",
    "location": "New York, NY",
}

# ── Simulated Phone OSINT Results ─────────────────────────────────────
SIMULATED_PHONE_RESULTS = {
    "+12125550134": {
        "carrier": "T-Mobile USA",
        "line_type": "Mobile",
        "country": "United States",
        "region": "New York, NY",
        "valid": True,
        "registered": "2019-03-14",
        "ported": False,
        "voip": False,
        "osint_note": "Corporate line; registered to NovaCrest Capital Group account. T-Mobile business plan.",
        "risk": "LOW — corporate managed line; carrier known",
    },
    "+19175550287": {
        "carrier": "AT&T Wireless",
        "line_type": "Mobile",
        "country": "United States",
        "region": "New York, NY",
        "valid": True,
        "registered": "2014-08-22",
        "ported": True,
        "ported_from": "Sprint",
        "voip": False,
        "osint_note": "Personal AT&T line; ported from Sprint in 2021. Long-standing number — higher value for social engineering.",
        "risk": "MEDIUM — personal line; SIM swap risk; longer history",
    },
}

# ── Simulated Social Media Footprint ──────────────────────────────────
SIMULATED_SOCIAL_FOOTPRINT = [
    {
        "platform": "LinkedIn",
        "username": "jhenderson-finance",
        "url": "https://www.linkedin.com/in/jhenderson-finance/",
        "status": "FOUND",
        "public": True,
        "intel": {
            "connections": 847,
            "title": "Senior Financial Analyst at NovaCrest Capital Group",
            "tenure": "NovaCrest (2021–present), Goldman Sachs (2017–2021), JPMorgan (2014–2017)",
            "education": "Columbia University, MS Finance 2014",
            "recent_activity": "Liked post: 'FinTech Summit 2026 Recap' — March 23, 2026",
            "mutual_connections": "16 mutual connections at NovaCrest",
        },
        "risk": "HIGH",
        "attacker_use": "Spearphishing lure customization; org chart mapping; connection harvesting for further targets",
    },
    {
        "platform": "Instagram",
        "username": "jhenderson_nyc",
        "url": "https://www.instagram.com/jhenderson_nyc/",
        "status": "FOUND",
        "public": True,
        "intel": {
            "followers": 847,
            "following": 412,
            "posts": 234,
            "bio": "NYC finance 📈 | Coffee addict ☕ | Weekend hiker 🥾",
            "tagged_locations": ["Javits Center", "Bryant Park", "Midtown Manhattan"],
            "geotagged_photos": 47,
            "last_post": "2026-06-10 (4 days before incident)",
        },
        "risk": "CRITICAL",
        "attacker_use": "Location tracking via geotagged photos; routine inference; personal interest profiling for social engineering",
    },
    {
        "platform": "Twitter / X",
        "username": "jhenderson_finance",
        "url": "https://twitter.com/jhenderson_finance",
        "status": "FOUND",
        "public": True,
        "intel": {
            "followers": 312,
            "tweets": 1847,
            "bio": "Financial analyst. Opinions my own. DMs open.",
            "recent_activity": [
                "Retweeted FinTech Summit agenda (March 2026)",
                "Replied to @NovaCrest_official post about Q1 results",
                "Quoted tweet about Bloomberg terminal shortcuts",
            ],
        },
        "risk": "HIGH",
        "attacker_use": "Employer confirmation; interest mapping; pretext development; scheduling intel from conference RSVPs",
    },
    {
        "platform": "GitHub",
        "username": "jhenderson85",
        "url": "https://github.com/jhenderson85",
        "status": "FOUND",
        "public": True,
        "intel": {
            "repos": 3,
            "repo_names": ["portfolio-analysis-py", "bloomberg-api-tools", "finance-utils"],
            "last_commit": "2026-04-12",
            "languages": ["Python", "R"],
            "sensitive_finding": "bloomberg-api-tools repo contains API key placeholder comments referencing 'novacrest-prod'",
        },
        "risk": "CRITICAL",
        "attacker_use": "Code reveals Bloomberg API integration patterns; comments may leak key naming conventions; Python skills confirm API access",
    },
    {
        "platform": "Strava",
        "username": "jhenderson_nyc",
        "url": "https://www.strava.com/athletes/jhenderson_nyc",
        "status": "FOUND",
        "public": True,
        "intel": {
            "activity_count": 312,
            "recent_runs": [
                "Central Park — Sat 07:15 (weekly pattern)",
                "Brooklyn Bridge Park — Sun 08:30",
                "Hudson River Greenway — weekday 06:45",
            ],
            "home_location_inferred": "Upper West Side (run start points cluster here)",
        },
        "risk": "HIGH",
        "attacker_use": "Home location inference (run start points); physical surveillance scheduling; impersonation of running app vendor",
    },
]

# ── Simulated Breach Exposure Data ────────────────────────────────────
SIMULATED_BREACH_DATA = [
    {
        "email": "jhenderson@novacrest.com",
        "breaches": [
            {
                "name": "LinkedIn 2021",
                "date": "2021-04-01",
                "data_types": ["Email addresses", "Names", "Phone numbers", "Job titles"],
                "severity": "Medium",
            },
        ],
        "pastes": 0,
        "risk": "MEDIUM — corporate email in LinkedIn breach; phone exposed",
    },
    {
        "email": "jhenderson85@gmail.com",
        "breaches": [
            {
                "name": "Adobe 2013",
                "date": "2013-10-04",
                "data_types": ["Email addresses", "Password hints", "Passwords"],
                "severity": "High",
            },
            {
                "name": "Collection #1 2019",
                "date": "2019-01-07",
                "data_types": ["Email addresses", "Passwords"],
                "severity": "Critical",
            },
        ],
        "pastes": 2,
        "risk": "CRITICAL — personal email has cracked password hashes; credential stuffing risk",
    },
]

# ── Simulated MDM Device Inventory (Jamf Pro) ─────────────────────────
SIMULATED_MDM_DEVICES = [
    {
        "device_id": "MDM-001",
        "serial": "DNPXQ2XYZABC",
        "owner": "j.henderson",
        "email": "jhenderson@novacrest.com",
        "model": "iPhone 15 Pro",
        "os_version": "17.4.1",
        "latest_available": "17.5",
        "is_supervised": True,
        "is_encrypted": True,
        "passcode_present": True,
        "jailbroken": False,
        "mdm_enrolled": True,
        "last_check_in": "2026-06-14T08:47:00Z",   # Check-in at phishing open time
        "managed_apps": [
            "Microsoft Outlook", "Microsoft Teams", "Bloomberg Professional",
            "CrowdStrike Falcon", "Zscaler", "Okta Verify",
        ],
        "unmanaged_apps_detected": ["WhatsApp", "Telegram", "Proton Mail"],
        "compliance_issues": [
            "OS version 17.4.1 — 17.5 available (minor patch pending)",
            "Unmanaged messaging apps with E2E encryption (Telegram, Proton Mail)",
        ],
        "last_location": {"lat": 40.748817, "lon": -73.985428, "timestamp": "2026-06-14T08:47:00Z"},
    },
    {
        "device_id": "MDM-002",
        "serial": "C4KXYZ8R1234",
        "owner": "m.torres",
        "email": "mtorres@novacrest.com",
        "model": "Samsung Galaxy S24",
        "os_version": "Android 14",
        "latest_available": "Android 14 (patch June 2026)",
        "is_supervised": False,    # Android enrolled as BYOD — less control
        "is_encrypted": True,
        "passcode_present": True,
        "jailbroken": False,
        "mdm_enrolled": True,
        "last_check_in": "2026-06-20T16:22:00Z",
        "managed_apps": ["Microsoft Outlook", "Microsoft Teams", "Okta Verify"],
        "unmanaged_apps_detected": ["Signal", "Dropbox", "Google Drive Personal"],
        "compliance_issues": [
            "BYOD enrollment (unsupervised) — MDM policy cannot enforce app removal",
            "Google Drive Personal — potential corporate data exfil channel",
            "Security patch level: May 2026 (June 2026 patch available)",
        ],
    },
    {
        "device_id": "MDM-003",
        "serial": "ABCXYZ999DEF",
        "owner": "s.chen",
        "email": "schen@novacrest.com",
        "model": "iPhone 14",
        "os_version": "16.7.4",   # Two major versions behind
        "latest_available": "17.5",
        "is_supervised": True,
        "is_encrypted": True,
        "passcode_present": False,  # NO SCREEN LOCK
        "jailbroken": False,
        "mdm_enrolled": True,
        "last_check_in": "2026-06-18T11:05:00Z",
        "managed_apps": ["Microsoft Outlook", "Bloomberg Professional", "Okta Verify"],
        "unmanaged_apps_detected": ["TikTok", "Snapchat", "Cash App"],
        "compliance_issues": [
            "CRITICAL: iOS 16.7.4 — two major versions behind; multiple CVEs unpatched",
            "CRITICAL: No screen lock / passcode — device data unprotected if lost",
            "TikTok installed — banned in US government contexts; data sovereignty risk",
        ],
    },
]


def run_phone_osint(subject: Dict, verbose: bool) -> List[Dict]:
    """Simulate phone number OSINT."""
    log.info("[MODULE 1] Phone Number OSINT")
    results = []
    for number in [subject.get("phone_corporate"), subject.get("phone_personal")]:
        if number and number in SIMULATED_PHONE_RESULTS:
            data = SIMULATED_PHONE_RESULTS[number]
            results.append({"number": number, **data})
            if verbose:
                log.info(f"  {number}: {data['carrier']} | {data['line_type']} | {data['risk']}")
    return results


def run_social_footprint(subject: Dict, verbose: bool) -> List[Dict]:
    """Simulate social media account enumeration."""
    log.info("[MODULE 2] Social Media Footprinting")
    results = []
    for profile in SIMULATED_SOCIAL_FOOTPRINT:
        results.append(profile)
        if verbose:
            icon = "🔴" if profile["risk"] == "CRITICAL" else "🟠"
            log.info(f"  {icon} {profile['platform']}: {profile['url']} [{profile['risk']}]")
            for key, val in profile["intel"].items():
                if isinstance(val, str) and len(val) < 80:
                    log.info(f"       {key}: {val}")
    return results


def run_breach_check(subject: Dict, verbose: bool) -> List[Dict]:
    """Simulate breach exposure check."""
    log.info("[MODULE 3] Breach Exposure Check")
    results = []
    for entry in SIMULATED_BREACH_DATA:
        results.append(entry)
        if verbose:
            log.info(f"  {entry['email']}: {len(entry['breaches'])} breach(es) — {entry['risk']}")
            for b in entry["breaches"]:
                log.info(f"    ↳ {b['name']} ({b['date']}) — {', '.join(b['data_types'][:2])}")
    return results


def run_mdm_audit(verbose: bool) -> Dict:
    """Simulate MDM device compliance audit."""
    log.info("[MODULE 4] MDM Device Compliance Audit (Jamf Pro)")
    devices = SIMULATED_MDM_DEVICES
    total = len(devices)
    critical_issues = sum(
        1 for d in devices
        if any("CRITICAL" in i for i in d.get("compliance_issues", []))
    )
    non_compliant = sum(
        1 for d in devices if d.get("compliance_issues")
    )

    if verbose:
        for d in devices:
            issues = d.get("compliance_issues", [])
            icon = "🔴" if any("CRITICAL" in i for i in issues) else "🟡" if issues else "✅"
            log.info(f"  {icon} {d['owner']} ({d['model']} iOS {d['os_version']})")
            for issue in issues:
                severity = "🔴" if "CRITICAL" in issue else "🟡"
                log.info(f"     {severity} {issue[:70]}")

    return {
        "total_devices": total,
        "non_compliant": non_compliant,
        "critical_issues": critical_issues,
        "devices": devices,
        "fleet_summary": {
            "ios_devices": sum(1 for d in devices if "iPhone" in d.get("model", "")),
            "android_devices": sum(1 for d in devices if "Samsung" in d.get("model", "")),
            "byod_devices": sum(1 for d in devices if not d.get("is_supervised")),
            "outdated_os": sum(1 for d in devices
                               if d.get("os_version", "") < "17.4"),
            "no_screen_lock": sum(1 for d in devices
                                   if not d.get("passcode_present")),
        },
    }


def emit_profile_report(phone: List, social: List,
                         breach: List, mdm: Dict) -> None:
    """Print unified mobile OSINT profile."""
    print("\n" + "=" * 70)
    print("  MOBILE OSINT PROFILE — Day 23")
    print("  Subject: j.henderson | NovaCrest Capital Group")
    print("=" * 70 + "\n")

    # Social: most dangerous findings
    critical_social = [s for s in social if s["risk"] == "CRITICAL"]
    print("CRITICAL INTELLIGENCE FINDINGS:")
    print("─" * 55)
    for s in critical_social:
        print(f"  🔴 {s['platform']}: {s['attacker_use'][:65]}")
    print()

    # MDM: fleet gaps
    print("MDM FLEET COMPLIANCE:")
    print("─" * 55)
    fleet = mdm.get("fleet_summary", {})
    print(f"  Total enrolled devices:  {mdm['total_devices']}")
    print(f"  Non-compliant:           {mdm['non_compliant']}")
    print(f"  Critical issues:         {mdm['critical_issues']}")
    print(f"  Outdated OS:             {fleet.get('outdated_os', 0)}")
    print(f"  No screen lock:          {fleet.get('no_screen_lock', 0)}")
    print(f"  BYOD (unsupervised):     {fleet.get('byod_devices', 0)}")
    print()

    # Breach summary
    print("BREACH EXPOSURE:")
    print("─" * 55)
    for b in breach:
        print(f"  {b['email']}: {len(b['breaches'])} breach(es) — {b['risk'][:40]}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Day 23 Mobile OSINT Profiler")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--subject", default="jhenderson")
    parser.add_argument("--mode", choices=["phone", "social", "breach", "mdm-audit", "all"],
                        default="all")
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--output", default="/tmp/mobile_osint_profile.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 23 — Mobile OSINT Profiler")
    log.info(" NovaCrest Capital Group | OSINT Track")
    log.info(" NOTE: All data is simulated for portfolio demonstration")
    log.info("=" * 70)
    log.info("")

    phone_results = run_phone_osint(SUBJECT, args.verbose)
    log.info("")
    social_results = run_social_footprint(SUBJECT, args.verbose)
    log.info("")
    breach_results = run_breach_check(SUBJECT, args.verbose)
    log.info("")
    mdm_results = run_mdm_audit(args.verbose)

    emit_profile_report(phone_results, social_results, breach_results, mdm_results)

    output = {
        "generated": datetime.datetime.utcnow().isoformat() + "Z",
        "subject": SUBJECT["alias"],
        "phone_osint": phone_results,
        "social_footprint": social_results,
        "breach_exposure": breach_results,
        "mdm_audit": mdm_results,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"\nProfile written: {args.output}")


if __name__ == "__main__":
    main()
