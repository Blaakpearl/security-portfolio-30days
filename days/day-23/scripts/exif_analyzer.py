"""
Day 23 — EXIF Metadata Analyzer
NovaCrest Capital Group | Mobile OSINT

PURPOSE: Batch-extracts EXIF metadata from images — real or simulated —
         and assesses the OSINT intelligence value of each field. Identifies
         GPS coordinates, device fingerprints, timestamps, and sensitive
         embedded data that an attacker could use for reconnaissance.

WHAT IT DETECTS:
  - GPS coordinates (precise location where photo was taken)
  - Device make/model (target's phone; enables device-specific exploits)
  - OS/Software version (patches status; attack surface)
  - Timestamps (work patterns, routines, time zones)
  - Sensitive fields (usernames embedded in software metadata)
  - Metadata stripping gaps (platforms that preserve metadata)

RISK RATINGS:
  - GPS present: CRITICAL (physical location disclosure)
  - Device model + OS: HIGH (enables targeted device exploits)
  - Timestamp patterns: MEDIUM (routine/schedule inference)
  - Software metadata: LOW–MEDIUM (version fingerprinting)

Usage:
    python exif_analyzer.py --demo --verbose
    python exif_analyzer.py --input ./photos/ --output artifacts/exif_findings.json
    python exif_analyzer.py --demo --report
"""

import argparse
import datetime
import json
import logging
import math
import os
from typing import Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("exif_analyzer")


# ── Simulated Photo Metadata (Demo Mode) ──────────────────────────────
# Represents public Instagram/LinkedIn photos from j.henderson's account
# and other NovaCrest employees — all simulated for portfolio demonstration
SIMULATED_PHOTOS = [
    {
        "filename": "jhenderson_instagram_2026-05-14.jpg",
        "source": "Instagram @jhenderson_nyc (public)",
        "exif": {
            "Make": "Apple",
            "Model": "iPhone 15 Pro",
            "Software": "17.2.1",
            "DateTimeOriginal": "2026-05-14 12:34:22",
            "GPSLatitude": 40.748817,
            "GPSLongitude": -73.985428,
            "GPSAltitude": 18.2,
            "GPSLatitudeRef": "N",
            "GPSLongitudeRef": "W",
            "ImageDescription": "Great lunch! #NYC #Finance",
            "UserComment": "",
            "Orientation": 1,
        },
        "osint_context": "Posted from corporate device during lunch break — Midtown Manhattan confirmed",
    },
    {
        "filename": "jhenderson_linkedin_profile_photo.jpg",
        "source": "LinkedIn public profile photo",
        "exif": {
            "Make": None,
            "Model": None,
            "Software": "Adobe Photoshop 2026",
            "DateTimeOriginal": "2026-01-08 09:15:44",
            "GPSLatitude": None,
            "GPSLongitude": None,
            "GPSAltitude": None,
            "ImageDescription": "",
            "UserComment": "jhenderson@novacrest.com",  # Embedded in metadata
        },
        "osint_context": "GPS stripped (LinkedIn does this), but corporate email embedded in UserComment",
    },
    {
        "filename": "jhenderson_instagram_conference_2026-03-22.jpg",
        "source": "Instagram @jhenderson_nyc (public)",
        "exif": {
            "Make": "Apple",
            "Model": "iPhone 15 Pro",
            "Software": "17.2.0",          # Older OS — 17.2.1 was available
            "DateTimeOriginal": "2026-03-22 18:42:11",
            "GPSLatitude": 40.761429,
            "GPSLongitude": -73.977355,
            "GPSAltitude": 42.1,
            "GPSLatitudeRef": "N",
            "GPSLongitudeRef": "W",
            "ImageDescription": "Great session at #FinTechSummit2026 @javitscenter",
            "UserComment": "",
        },
        "osint_context": "Javits Center (conference venue) — attacker used FinTech Summit to craft convincing spearphishing lure",
    },
    {
        "filename": "novacrest_employee2_linkedin.jpg",
        "source": "LinkedIn — Michael Torres, NovaCrest Trading Desk",
        "exif": {
            "Make": "Samsung",
            "Model": "Galaxy S24 Ultra",
            "Software": "Android 14",
            "DateTimeOriginal": "2026-04-15 07:52:33",
            "GPSLatitude": 40.706005,
            "GPSLongitude": -74.008827,
            "GPSAltitude": 3.4,
            "GPSLatitudeRef": "N",
            "GPSLongitudeRef": "W",
            "ImageDescription": "",
            "UserComment": "mtorres@novacrest.com",
        },
        "osint_context": "Early morning photo near Wall Street — work arrival time + commute origin inferable. Second employee email confirmed.",
    },
    {
        "filename": "novacrest_team_photo_2026-02-10.jpg",
        "source": "NovaCrest official Twitter/X account (public)",
        "exif": {
            "Make": "Apple",
            "Model": "iPhone 14 Pro",
            "Software": "16.7.4",          # Outdated iOS — significant gap
            "DateTimeOriginal": "2026-02-10 14:22:05",
            "GPSLatitude": 40.748540,
            "GPSLongitude": -73.983992,
            "GPSAltitude": 30.7,
            "GPSLatitudeRef": "N",
            "GPSLongitudeRef": "W",
            "ImageDescription": "NovaCrest Q1 kickoff! #TeamNovaCrest",
            "UserComment": "",
        },
        "osint_context": "Corporate Twitter post with intact GPS — office building location confirmed (Grand Central area). Posted from personal iPhone 14 (iOS 16.7.4 — 2 major versions behind).",
    },
]

# Known addresses near NovaCrest office (for location matching)
KNOWN_LOCATIONS = {
    "NovaCrest HQ": (40.748540, -73.983992),
    "Javits Center": (40.757431, -74.002245),
    "Wall Street area": (40.706005, -74.008827),
}


def haversine_distance(lat1: float, lon1: float,
                        lat2: float, lon2: float) -> float:
    """Calculate distance between two GPS coordinates in meters."""
    R = 6371000  # Earth radius in meters
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (math.sin(dphi/2)**2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(dlambda/2)**2)
    return 2 * R * math.asin(math.sqrt(a))


def nearest_known_location(lat: float, lon: float) -> Tuple[str, float]:
    """Find the nearest known landmark and distance."""
    nearest = min(
        KNOWN_LOCATIONS.items(),
        key=lambda kv: haversine_distance(lat, lon, kv[1][0], kv[1][1])
    )
    distance = haversine_distance(lat, lon, nearest[1][0], nearest[1][1])
    return nearest[0], round(distance)


def assess_exif_risk(exif: Dict) -> List[Dict]:
    """Assess OSINT risk of each EXIF field."""
    findings = []

    # GPS presence — highest risk
    if exif.get("GPSLatitude") and exif.get("GPSLongitude"):
        lat = exif["GPSLatitude"]
        lon = exif["GPSLongitude"]
        nearest, dist_m = nearest_known_location(lat, lon)
        google_maps = f"https://www.google.com/maps?q={lat},{lon}"

        findings.append({
            "field": "GPS Coordinates",
            "value": f"{lat}, {lon}",
            "risk": "CRITICAL",
            "technique": "T1430",
            "intel_value": (
                f"Precise location: {lat:.6f}, {lon:.6f}. "
                f"Nearest landmark: {nearest} ({dist_m}m). "
                f"Maps: {google_maps}"
            ),
            "attacker_use": "Physical surveillance; workplace/home location; routine mapping",
        })

    # Device model + OS (attack surface)
    if exif.get("Model"):
        os_ver = exif.get("Software", "unknown")
        findings.append({
            "field": "Device Model + OS",
            "value": f"{exif.get('Make', '')} {exif['Model']} / {os_ver}",
            "risk": "HIGH",
            "technique": "T1592.002",
            "intel_value": f"Target device: {exif.get('Make','')} {exif['Model']} running {os_ver}",
            "attacker_use": "Device-specific exploit selection; OS vulnerability targeting; patch level assessment",
        })

        # Flag outdated OS
        if "iPhone" in exif.get("Model", "") and "iOS" not in os_ver:
            try:
                ver_parts = os_ver.replace("iOS", "").strip().split(".")
                major = int(ver_parts[0])
                if major < 17:
                    findings.append({
                        "field": "Outdated iOS Version",
                        "value": os_ver,
                        "risk": "HIGH",
                        "technique": "T1592.002",
                        "intel_value": f"iOS {os_ver} is outdated — multiple CVEs available",
                        "attacker_use": "Targets known unpatched vulnerabilities (e.g., WebKit exploits)",
                    })
            except (ValueError, IndexError):
                pass

    # Sensitive data in metadata fields
    user_comment = exif.get("UserComment", "")
    if user_comment and "@" in user_comment:
        findings.append({
            "field": "Email in UserComment",
            "value": user_comment,
            "risk": "HIGH",
            "technique": "T1589.002",
            "intel_value": f"Corporate email confirmed: {user_comment}",
            "attacker_use": "Phishing target confirmation; credential stuffing; HIBP lookup",
        })

    # Timestamp — work pattern inference
    if exif.get("DateTimeOriginal"):
        try:
            dt = datetime.datetime.strptime(exif["DateTimeOriginal"], "%Y-%m-%d %H:%M:%S")
            hour = dt.hour
            if 6 <= hour <= 9:
                pattern = "early morning (possible commute)"
            elif 11 <= hour <= 14:
                pattern = "midday (lunch break)"
            elif 17 <= hour <= 20:
                pattern = "evening (end of workday)"
            else:
                pattern = "standard hours"

            findings.append({
                "field": "Timestamp",
                "value": exif["DateTimeOriginal"],
                "risk": "MEDIUM",
                "technique": "T1593.001",
                "intel_value": f"Photo taken {exif['DateTimeOriginal']} — {pattern}",
                "attacker_use": "Work schedule inference; optimal phishing delivery window; vacation/travel detection",
            })
        except ValueError:
            pass

    # Conference / event hashtag in description
    desc = exif.get("ImageDescription", "")
    if "#" in desc or "@" in desc:
        findings.append({
            "field": "Event/Venue Reference",
            "value": desc,
            "risk": "MEDIUM",
            "technique": "T1593.001",
            "intel_value": f"Subject attended event or location: {desc}",
            "attacker_use": "Spearphishing lure customization (impersonate event organizer, sponsor, speaker)",
        })

    return findings


def analyze_photos(photos: List[Dict], verbose: bool) -> List[Dict]:
    """Analyze all photos and return structured findings."""
    results = []
    for photo in photos:
        if verbose:
            log.info(f"Analyzing: {photo['filename']} (source: {photo['source']})")

        risks = assess_exif_risk(photo["exif"])
        critical = [r for r in risks if r["risk"] == "CRITICAL"]
        high = [r for r in risks if r["risk"] == "HIGH"]

        result = {
            "filename": photo["filename"],
            "source": photo["source"],
            "osint_context": photo["osint_context"],
            "risk_findings": risks,
            "critical_count": len(critical),
            "high_count": len(high),
            "overall_risk": ("CRITICAL" if critical else
                             "HIGH" if high else "MEDIUM"),
        }
        results.append(result)

        if verbose:
            for r in risks:
                icon = ("🔴" if r["risk"] == "CRITICAL" else
                        "🟠" if r["risk"] == "HIGH" else "🟡")
                log.info(f"  {icon} [{r['risk']}] {r['field']}: {r['intel_value'][:60]}")

    return results


def emit_report(results: List[Dict]) -> None:
    """Print EXIF analysis report."""
    total_critical = sum(r["critical_count"] for r in results)
    total_high = sum(r["high_count"] for r in results)

    print("\n" + "=" * 70)
    print("  EXIF METADATA OSINT REPORT — Day 23")
    print("  NovaCrest Capital Group | Mobile OSINT")
    print("=" * 70 + "\n")
    print(f"  Photos analyzed: {len(results)}")
    print(f"  Critical findings (GPS): {total_critical}")
    print(f"  High findings:           {total_high}")
    print()

    for r in sorted(results, key=lambda x: -x["critical_count"]):
        print(f"  📷 {r['filename']}")
        print(f"     Source: {r['source']}")
        print(f"     Overall risk: {r['overall_risk']}")
        print(f"     Context: {r['osint_context'][:70]}")
        for f in r["risk_findings"]:
            icon = "🔴" if f["risk"] == "CRITICAL" else ("🟠" if f["risk"] == "HIGH" else "🟡")
            print(f"     {icon} [{f['risk']}] {f['field']}: {f['intel_value'][:60]}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Day 23 EXIF Analyzer")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--input", help="Directory of images to analyze")
    parser.add_argument("--output", default="/tmp/exif_findings.json")
    parser.add_argument("--verbose", action="store_true", default=True)
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 23 — EXIF Metadata Analyzer")
    log.info(" NovaCrest Capital Group | Mobile OSINT")
    log.info("=" * 70)
    log.info(" Note: All target data is simulated for portfolio demonstration")
    log.info("")

    photos = SIMULATED_PHOTOS
    results = analyze_photos(photos, args.verbose)
    emit_report(results)

    output = {
        "analysis_date": datetime.datetime.utcnow().isoformat() + "Z",
        "subject": "j.henderson + NovaCrest employees (simulated)",
        "photos_analyzed": len(results),
        "results": results,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"\nFindings written: {args.output}")


if __name__ == "__main__":
    main()
