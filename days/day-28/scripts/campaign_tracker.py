"""
Day 28 — Campaign Tracker
NovaCrest Capital Group | OSINT Investigation

PURPOSE: Correlates the four confirmed FIN-NC-001 victim incidents to identify
         campaign timing patterns, target selection cadence, infrastructure
         rotation behavior, and operational tempo. Produces a timeline suitable
         for law enforcement briefing and predicts the next likely campaign window.

CORRELATION SOURCES:
  - Passive DNS first_seen dates (domain registration → victim targeting)
  - Certificate transparency issuance dates
  - Ransomwatch victim publication dates
  - NovaCrest forensic record (Days 15-27)
  - Dark web monitoring (leak site post dates)

Usage:
    python campaign_tracker.py --demo --verbose
    python campaign_tracker.py --demo --predict-next
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
log = logging.getLogger("campaign_tracker")


CONFIRMED_VICTIMS = [
    {
        "id": "VICTIM-001",
        "name": "Redacted UK Private Equity",
        "sector": "Private Equity",
        "geography": "UK",
        "aum_estimate_b": 2.1,
        "timeline": {
            "domain_registered": "2026-03-08",
            "cert_issued": "2026-03-10",
            "phishing_delivery": "2026-03-14",
            "estimated_access": "2026-03-14",
            "ransomware_deployed": "2026-03-19",
            "ransom_deadline": "2026-03-22",
            "leak_posted": "2026-04-05",      # Did not pay — published
            "data_published": True,
        },
        "ransom_demanded_xmr": 68.4,
        "ransom_usd_equiv": 2_100_000,
        "paid": False,
        "dwell_days": 5,
        "exfil_gb_estimate": 67,
        "phishing_lure": "ESG Investor Summit 2026 follow-up",
        "c2_domain": "secure-trading-api.financedocs.net",
    },
    {
        "id": "VICTIM-002",
        "name": "Redacted EU Asset Manager",
        "sector": "Asset Management",
        "geography": "EU (NL)",
        "aum_estimate_b": 2.6,
        "timeline": {
            "domain_registered": "2026-03-28",
            "cert_issued": "2026-03-30",
            "phishing_delivery": "2026-04-03",
            "estimated_access": "2026-04-03",
            "ransomware_deployed": "2026-04-08",
            "ransom_deadline": "2026-04-11",
            "leak_posted": "2026-03-30",       # Did not pay — published
            "data_published": True,
        },
        "ransom_demanded_xmr": 84.3,
        "ransom_usd_equiv": 2_600_000,
        "paid": False,
        "dwell_days": 5,
        "exfil_gb_estimate": 42,
        "phishing_lure": "Q1 Institutional Investor Summit recap",
        "c2_domain": "updates-cdn.financialdata.net",
    },
    {
        "id": "VICTIM-003",
        "name": "Redacted US Hedge Fund",
        "sector": "Hedge Fund",
        "geography": "US",
        "aum_estimate_b": 3.1,
        "timeline": {
            "domain_registered": "2026-04-25",
            "cert_issued": "2026-04-28",
            "phishing_delivery": "2026-05-02",
            "estimated_access": "2026-05-02",
            "ransomware_deployed": "2026-05-07",
            "ransom_deadline": "2026-05-10",
            "leak_posted": "2026-05-12",       # Paid — removed from site
            "data_published": False,
        },
        "ransom_demanded_xmr": 98.4,
        "ransom_usd_equiv": 3_100_000,
        "paid": True,
        "negotiated_discount_pct": 35,
        "dwell_days": 5,
        "exfil_gb_estimate": 91,
        "phishing_lure": "Private Credit Forum 2026 materials",
        "c2_domain": "telemetry.marketsync.io",
    },
    {
        "id": "VICTIM-004",
        "name": "NovaCrest Capital Group",
        "sector": "Investment Management",
        "geography": "US",
        "aum_estimate_b": 4.2,
        "timeline": {
            "domain_registered": "2026-06-08",
            "cert_issued": "2026-06-09",
            "phishing_delivery": "2026-06-14",
            "estimated_access": "2026-06-14T08:47:00Z",
            "ransomware_deployed": "2026-06-19T03:22:45Z",
            "ransom_deadline": "2026-06-22T06:14:00Z",
            "leak_posted": "2026-06-19",
            "data_published": False,           # Deadline not yet passed
        },
        "ransom_demanded_xmr": 127.4,
        "ransom_usd_equiv": 4_200_000,
        "paid": False,
        "dwell_days": 5,
        "exfil_gb_confirmed": 0.293,           # GB — confirmed in forensic record
        "phishing_lure": "FinTech Summit 2026 Q3 Investment Strategy follow-up",
        "c2_domain": "trading-updates.novacrest-secure.com",
    },
]


def analyze_timing_patterns(victims: List[Dict], verbose: bool) -> Dict:
    """Extract operational timing patterns from victim timeline data."""
    patterns = {
        "domain_to_cert_days": [],
        "cert_to_phishing_days": [],
        "access_to_ransomware_days": [],
        "campaign_spacing_days": [],
        "preferred_attack_weekday": {},
    }

    phishing_dates = []
    for v in victims:
        tl = v["timeline"]
        reg = datetime.date.fromisoformat(tl["domain_registered"])
        cert = datetime.date.fromisoformat(tl["cert_issued"])
        phish = datetime.date.fromisoformat(tl["phishing_delivery"])
        access = datetime.date.fromisoformat(tl["estimated_access"][:10])
        ransom = datetime.date.fromisoformat(tl["ransomware_deployed"][:10])

        patterns["domain_to_cert_days"].append((cert - reg).days)
        patterns["cert_to_phishing_days"].append((phish - cert).days)
        patterns["access_to_ransomware_days"].append((ransom - access).days)

        day_name = phish.strftime("%A")
        patterns["preferred_attack_weekday"][day_name] = \
            patterns["preferred_attack_weekday"].get(day_name, 0) + 1

        phishing_dates.append(phish)

    # Campaign spacing
    phishing_dates.sort()
    for i in range(1, len(phishing_dates)):
        spacing = (phishing_dates[i] - phishing_dates[i-1]).days
        patterns["campaign_spacing_days"].append(spacing)

    def avg(lst): return round(sum(lst) / len(lst), 1) if lst else 0

    analysis = {
        "avg_domain_to_cert_days": avg(patterns["domain_to_cert_days"]),
        "avg_cert_to_phishing_days": avg(patterns["cert_to_phishing_days"]),
        "avg_access_to_ransomware_days": avg(patterns["access_to_ransomware_days"]),
        "avg_campaign_spacing_days": avg(patterns["campaign_spacing_days"]),
        "preferred_attack_days": patterns["preferred_attack_weekday"],
        "total_confirmed_victims": len(victims),
        "paid_count": sum(1 for v in victims if v["paid"]),
        "published_count": sum(1 for v in victims if v["timeline"]["data_published"]),
        "total_ransom_demanded_usd": sum(v["ransom_usd_equiv"] for v in victims),
        "avg_dwell_days": avg([v["dwell_days"] for v in victims]),
        "aum_range": f"${min(v['aum_estimate_b'] for v in victims):.1f}B — ${max(v['aum_estimate_b'] for v in victims):.1f}B",
    }

    if verbose:
        log.info(f"  Avg domain→cert: {analysis['avg_domain_to_cert_days']} days")
        log.info(f"  Avg cert→phishing: {analysis['avg_cert_to_phishing_days']} days")
        log.info(f"  Avg access→ransomware: {analysis['avg_access_to_ransomware_days']} days (dwell time)")
        log.info(f"  Avg campaign spacing: {analysis['avg_campaign_spacing_days']} days (~{analysis['avg_campaign_spacing_days']//30} months)")
        log.info(f"  Victims paid: {analysis['paid_count']}/{len(victims)}")
        log.info(f"  Total demanded: ${analysis['total_ransom_demanded_usd']:,}")
        log.info(f"  Target AUM range: {analysis['aum_range']}")

    return analysis


def predict_next_campaign(victims: List[Dict], patterns: Dict) -> Dict:
    """Predict next campaign timing and target profile."""
    last_phishing = max(
        datetime.date.fromisoformat(v["timeline"]["phishing_delivery"])
        for v in victims
    )
    next_estimated = last_phishing + datetime.timedelta(
        days=int(patterns["avg_campaign_spacing_days"])
    )
    infra_prep_start = next_estimated - datetime.timedelta(
        days=int(patterns["avg_cert_to_phishing_days"] +
                 patterns["avg_domain_to_cert_days"])
    )

    return {
        "last_known_phishing": str(last_phishing),
        "next_campaign_estimated": str(next_estimated),
        "infra_prep_estimated_start": str(infra_prep_start),
        "target_profile": {
            "sector": "Financial services (investment management, hedge fund, PE)",
            "aum_range": "$2B–$6B (escalating 20% per campaign)",
            "geography": "US or EU (alternating pattern)",
            "lure_theme": "Financial conference or sector forum follow-up",
            "expected_ransom": "$5–7M USD (scaling with AUM)",
        },
        "early_warning_indicators": [
            "New domain registered with finance/trading theme in Namecheap/GoDaddy",
            "Let's Encrypt cert issued to that domain within 2 days",
            "Domain resolves to AS209588 (Flyservers) IP range",
            "Shodan scan shows nginx on port 443 with Sliver JARM",
            "Conference spearphishing targeting $2B+ AUM firms",
        ],
        "confidence": "MEDIUM — based on 4-victim sample; pattern could vary",
    }


def emit_campaign_timeline(victims: List[Dict]) -> None:
    """Print formatted campaign timeline."""
    print("\n  CAMPAIGN TIMELINE — FIN-NC-001")
    print("  " + "─" * 72)
    print(f"  {'DATE':12} {'VICTIM':30} {'EVENT':28} {'OUTCOME'}")
    print("  " + "─" * 72)

    events = []
    for v in victims:
        tl = v["timeline"]
        short_name = v["name"].replace("Redacted ", "")
        events += [
            (tl["domain_registered"], short_name, "Domain registered", ""),
            (tl["phishing_delivery"], short_name, "Phishing delivered", ""),
            (tl["ransomware_deployed"][:10], short_name, "Ransomware deployed", ""),
            (tl["leak_posted"], short_name, "Leak site posted",
             "DATA PUBLISHED" if tl["data_published"] else
             "PAID" if v["paid"] else "ACTIVE" if not tl["data_published"] else ""),
        ]

    for date, victim, event, outcome in sorted(events):
        flag = f" ← {outcome}" if outcome else ""
        print(f"  {date:12} {victim:30} {event:28}{flag}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Day 28 Campaign Tracker")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--predict-next", action="store_true", default=True)
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--output", default="/tmp/day28_campaign_analysis.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 28 — Campaign Tracker | FIN-NC-001")
    log.info(f" Confirmed victims: {len(CONFIRMED_VICTIMS)}")
    log.info("=" * 70)
    log.info("")

    log.info("[1] Campaign Timing Pattern Analysis")
    patterns = analyze_timing_patterns(CONFIRMED_VICTIMS, args.verbose)
    log.info("")

    emit_campaign_timeline(CONFIRMED_VICTIMS)

    if args.predict_next:
        log.info("[2] Next Campaign Prediction")
        prediction = predict_next_campaign(CONFIRMED_VICTIMS, patterns)
        log.info(f"  Last phishing: {prediction['last_known_phishing']}")
        log.info(f"  Next estimated: {prediction['next_campaign_estimated']}")
        log.info(f"  Infra prep likely: {prediction['infra_prep_estimated_start']}")
        log.info(f"  Target profile: {prediction['target_profile']['aum_range']}")
        log.info(f"  Expected ransom: {prediction['target_profile']['expected_ransom']}")
        log.info("")
        log.info("  Early warning indicators:")
        for i, indicator in enumerate(prediction["early_warning_indicators"], 1):
            log.info(f"    {i}. {indicator}")
    else:
        prediction = {}

    output = {
        "victims": CONFIRMED_VICTIMS,
        "timing_patterns": patterns,
        "next_campaign_prediction": prediction,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"\nCampaign analysis written: {args.output}")


if __name__ == "__main__":
    main()
