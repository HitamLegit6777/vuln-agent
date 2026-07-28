"""Verify AI-ready context blob + NVD parser correctness."""
import asyncio, sys, json
sys.path.insert(0, ".")
from scrapers.registry import build_scrapers, get_all
from scrapers.nvd import NVDScraper
from scrapers.base import AffectedRange

SAMPLE = {
  "id": "CVE-2024-9999",
  "descriptions": [{"lang":"en","value":"Test vuln in FooPlugin. RCE via deserialization."}],
  "references": [
    {"url":"https://example.com/advisory"},
    {"url":"https://github.com/foo/bar/commit/abc123"},
    {"url":"https://www.exploit-db.com/exploits/99999"},
  ],
  "metrics": {"cvssMetricV31":[{"cvssData":{"baseSeverity":"CRITICAL","baseScore":9.8}}]},
  "published": "2024-01-01T00:00:00",
  "configurations": [{"nodes":[{"cpeMatch":[
    {"vulnerable":True,"criteria":"cpe:2.3:a:foo:bar:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0","versionEndExcluding":"1.5"},
    {"vulnerable":False,"criteria":"cpe:2.3:a:foo:bar:1.5:*:*:*:*:*:*:*"},
  ]}]}],
}

def test_nvd_parser():
    s = NVDScraper()
    r = s._parse_cve(SAMPLE, "1.3")
    assert r.cve == "CVE-2024-9999", r.cve
    assert r.severity == "CRITICAL", r.severity
    assert r.cvss == 9.8, r.cvss
    assert len(r.affected) == 1, r.affected        # only vulnerable=true CPE
    a = r.affected[0]
    assert a.product == "bar", a
    assert a.min_inclusive == "1.0" and a.max_exclusive == "1.5", a
    assert r.diff_patch == "https://github.com/foo/bar/commit/abc123", r.diff_patch
    assert any("exploit-db" in u for u in r.poc_refs), r.poc_refs
    # version match: 1.3 vulnerable, 1.5 not, 0.9 not
    assert a.matches("1.3") is True, a.matches("1.3")
    assert a.matches("1.5") is False, a.matches("1.5")
    assert a.matches("0.9") is False, a.matches("0.9")
    print("NVD parser: PASS  (cve/sev/cvss/range/match/diff_patch/poc_refs)")

async def main():
    test_nvd_parser()
    print("\n##### get_all('CVE-2024-25641') merged AI context #####\n")
    scrapers = build_scrapers()
    recs = await get_all(scrapers, "CVE-2024-25641")
    print(f"merged records: {len(recs)}")
    if recs:
        r = recs[0]
        print(f"merged_sources: {r.raw.get('merged_sources')}")
        print(f"poc_refs count: {len(r.poc_refs)}  diff_patch: {r.diff_patch}")
        print(f"has exploit_source: {bool(r.raw.get('exploit_source'))}")
        print(f"description len: {len(r.description)}")
        print("\n========== to_ai_context() ==========")
        print(r.to_ai_context()[:2500])
    for s in scrapers: await s.close()

asyncio.run(main())
