"""
IOC Extractor — Parse raw text/logs and extract indicators of compromise.
"""
import re, json, sys

PATTERNS = {
    "ipv4":   r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    "md5":    r'\b[a-fA-F0-9]{32}\b',
    "sha1":   r'\b[a-fA-F0-9]{40}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "url":    r'https?://[^\s<>"{}|\\^`\[\]]+',
    "email":  r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b',
    "cve":    r'CVE-\d{4}-\d{4,7}',
}

PRIVATE = re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)')

def extract(text: str) -> dict:
    results = {}
    for name, pat in PATTERNS.items():
        hits = list(set(re.findall(pat, text)))
        if name == "ipv4":
            hits = [ip for ip in hits if not PRIVATE.match(ip)]
        if hits:
            results[name] = hits
    return results

if __name__ == "__main__":
    sample = sys.stdin.read() if not sys.stdin.isatty() else \
        "Contacted 185.220.101.45 and evil-domain.ru. Hash: d41d8cd98f00b204e9800998ecf8427e"
    print(json.dumps(extract(sample), indent=2))
