#!/usr/bin/env python3
"""Fetch cybersecurity news from open sources and write data/news.json.

Standard library only, so the GitHub Action needs no pip install.
Each source is fetched independently: one failing source never breaks the run.
"""
import json, re, sys, html, hashlib
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "news.json"
MAX_ITEMS = 500
MAX_AGE_DAYS = 30
UA = "Mozilla/5.0 (compatible; CyberNewsBot/1.0)"

# (name, url, category)
# Category "news" = guess from keywords. Category starting with "=" = always use it
# (good for advisory feeds where every item is the same kind of thing).
RSS_SOURCES = [
    # --- News sites ---
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "news"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "news"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/", "news"),
    ("SecurityWeek", "https://feeds.feedburner.com/securityweek", "news"),
    ("The Record", "https://therecord.media/feed", "news"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml", "news"),
    ("Schneier on Security", "https://www.schneier.com/feed/atom/", "news"),
    ("SANS Internet Storm Center", "https://isc.sans.edu/rssfeed.xml", "news"),
    # --- Government and coordination centres ---
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "news"),
    ("CERT/CC Vulnerability Notes", "https://www.kb.cert.org/vulfeed/", "=vuln"),
    # --- Vendor advisories and patches ---
    ("Microsoft Security Response Center", "https://api.msrc.microsoft.com/update-guide/rss", "=patch"),
    ("Cisco Security Advisories", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", "=vuln"),
    ("Fortinet PSIRT", "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "=vuln"),
    ("Palo Alto Advisories", "https://security.paloaltonetworks.com/rss.xml", "=vuln"),
    ("Ubuntu Security Notices", "https://ubuntu.com/security/notices/rss.xml", "=patch"),
    ("Chrome Releases", "https://chromereleases.googleblog.com/feeds/posts/default", "=patch"),
    # --- Threat research ---
    ("Google Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default", "=vuln"),
    ("Google Threat Intelligence", "https://cloud.google.com/blog/topics/threat-intelligence/rss/", "threat"),
    ("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/", "threat"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/", "news"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/", "news"),
    ("CrowdStrike", "https://www.crowdstrike.com/en-us/blog/feed/", "news"),
    ("Securelist", "https://securelist.com/feed/", "news"),
    ("ESET WeLiveSecurity", "https://www.welivesecurity.com/en/feed/", "news"),
    ("Check Point Research", "https://research.checkpoint.com/feed/", "news"),
    ("GitHub Security Blog", "https://github.blog/security/feed/", "news"),
    # --- Exploits ---
    ("Exploit-DB", "https://www.exploit-db.com/rss.xml", "=exploit"),
    # --- Community (Reddit may block GitHub's servers; failures are skipped) ---
    ("Reddit r/netsec", "https://www.reddit.com/r/netsec/.rss", "news"),
    ("Reddit r/cybersecurity", "https://www.reddit.com/r/cybersecurity/.rss", "news"),
]

# Keep each source from crowding out the others
DEFAULT_CAP = 40
SOURCE_CAP = {"Ubuntu Security Notices": 15, "Microsoft Security Response Center": 20,
              "Cisco Security Advisories": 20, "Chrome Releases": 10, "ransomware.live": 60}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"
RANSOMWARE_URL = "https://api.ransomware.live/v2/recentvictims"

# Category keywords, checked in order. First match wins.
CATEGORY_RULES = [
    ("ransomware", r"ransomware|lockbit|blackcat|alphv|clop|akira|extortion"),
    ("breach", r"data breach|breached|leaked|data leak|stolen data|exposed data|dark ?web"),
    ("exploit", r"exploit|proof[- ]of[- ]concept|\bpoc\b|zero[- ]day|0-day|actively exploited"),
    ("patch", r"patch(es|ed)?\b|security update|hotfix|patch tuesday"),
    ("vuln", r"cve-\d{4}-\d+|vulnerabilit|\bflaw|\brce\b|remote code execution"),
    ("threat", r"malware|botnet|phishing|\bapt\d*|backdoor|trojan|spyware|campaign|threat actor|attack"),
]


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def clean(text, limit=280):
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = html.unescape(re.sub(r"\s+", " ", text)).strip()
    text = re.sub(r"\s*\[(\.\.\.|…|&#8230;)\]\s*$", "", text)
    text = re.sub(r"\s*The post .{0,200}appeared first on .*$", "", text)
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


def categorize(title, summary, default):
    if default.startswith("="):
        return default[1:]
    blob = f"{title} {summary}".lower()
    for cat, pattern in CATEGORY_RULES:
        if re.search(pattern, blob):
            return cat
    return default if default != "news" else "threat"


def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        dt = parsedate_to_datetime(s)
    except Exception:
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def make_id(*parts):
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


def local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_feed(xml_bytes, source, default_kind):
    root = ET.fromstring(xml_bytes)
    items = []
    for node in root.iter():
        if local(node.tag) not in ("item", "entry"):
            continue
        f = {}
        for child in node:
            name = local(child.tag)
            if name == "link":
                f.setdefault("link", child.get("href") or (child.text or "").strip())
            elif name in ("title", "description", "summary", "content",
                          "pubDate", "published", "updated", "date"):
                f.setdefault(name, child.text or "")
        link, title = f.get("link", ""), clean(f.get("title", ""), 200)
        if not link or not title:
            continue
        date = parse_date(f.get("pubDate") or f.get("published")
                          or f.get("updated") or f.get("date"))
        summary = clean(f.get("description") or f.get("summary") or f.get("content") or "")
        items.append({
            "id": make_id(link),
            "title": title,
            "url": link,
            "summary": summary,
            "source": source,
            "category": categorize(title, summary, default_kind),
            "date": (date or datetime.now(timezone.utc)).isoformat(),
        })
    return items


def from_kev():
    data = json.loads(fetch(KEV_URL))
    items = []
    for v in data.get("vulnerabilities", [])[-60:]:
        cve = v.get("cveID", "")
        date = parse_date(v.get("dateAdded"))
        desc = clean(v.get("shortDescription", ""))
        items.append({
            "id": make_id("kev", cve),
            "title": f"{cve}: {v.get('vulnerabilityName', '')} ({v.get('vendorProject', '')} {v.get('product', '')})",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "summary": desc,
            "source": "CISA KEV",
            "category": "exploit",
            "badge": "Actively exploited",
            "date": (date or datetime.now(timezone.utc)).isoformat(),
        })
    return items


def from_hibp():
    data = json.loads(fetch(HIBP_URL))
    data.sort(key=lambda b: b.get("AddedDate", ""), reverse=True)
    items = []
    for b in data[:25]:
        date = parse_date(b.get("AddedDate"))
        count = b.get("PwnCount", 0)
        classes = ", ".join(b.get("DataClasses", [])[:5])
        items.append({
            "id": make_id("hibp", b.get("Name", "")),
            "title": f"{b.get('Title', b.get('Name', 'Unknown'))} breach: {count:,} accounts",
            "url": "https://haveibeenpwned.com/PwnedWebsites#" + b.get("Name", ""),
            "summary": (f"Exposed data: {classes}. " if classes else "") + clean(b.get("Description", ""), 200),
            "source": "Have I Been Pwned",
            "category": "breach",
            "date": (date or datetime.now(timezone.utc)).isoformat(),
        })
    return items


def from_ransomware():
    """Metadata only: group, victim name, country, date. No stolen data is fetched or stored."""
    data = json.loads(fetch(RANSOMWARE_URL))
    if isinstance(data, dict):
        data = data.get("victims") or data.get("data") or []
    items = []
    for v in data[:60]:
        victim = v.get("victim") or v.get("post_title") or "Unnamed organization"
        group = v.get("group") or v.get("group_name") or "Unknown group"
        date = parse_date(v.get("discovered") or v.get("attackdate") or v.get("published"))
        country = v.get("country") or ""
        items.append({
            "id": make_id("rw", group, victim),
            "title": f"{group} claims attack on {victim}",
            "url": v.get("permalink") or f"https://www.ransomware.live/group/{group}",
            "summary": "Listed on a ransomware group's leak site"
                       + (f" ({country})" if country else "")
                       + ". This is the group's claim and is not independently verified.",
            "source": "ransomware.live",
            "category": "ransomware",
            "badge": "Dark web listing",
            "date": (date or datetime.now(timezone.utc)).isoformat(),
        })
    return items


def main():
    collected, status = [], {}
    jobs = [(name, (lambda u=url, n=name, k=kind: parse_feed(fetch(u), n, k)))
            for name, url, kind in RSS_SOURCES]
    jobs += [("CISA KEV", from_kev), ("Have I Been Pwned", from_hibp),
             ("ransomware.live", from_ransomware)]
    for name, job in jobs:
        try:
            got = job()
            collected += got
            status[name] = f"ok ({len(got)})"
        except Exception as e:
            status[name] = f"failed: {type(e).__name__}"

    # Merge with the previous run so items persist if a source is briefly down
    if OUT.exists():
        try:
            collected += json.loads(OUT.read_text()).get("items", [])
        except Exception:
            pass

    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)
    unique = {}
    for it in collected:
        d = parse_date(it["date"])
        if it["id"] not in unique and d and d >= cutoff:
            unique[it["id"]] = it
    items, per_source = [], {}
    for it in sorted(unique.values(), key=lambda i: i["date"], reverse=True):
        n = per_source.get(it["source"], 0)
        if n < SOURCE_CAP.get(it["source"], DEFAULT_CAP):
            per_source[it["source"]] = n + 1
            items.append(it)
    items = items[:MAX_ITEMS]

    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(
        {"updated": datetime.now(timezone.utc).isoformat(), "sources": status, "items": items},
        ensure_ascii=False, indent=1))
    for k, v in status.items():
        print(f"{k}: {v}")
    print(f"Wrote {len(items)} items")
    if all(v.startswith("failed") for v in status.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
