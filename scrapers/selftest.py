"""Self-test: exercise scrapers against live endpoints. Run: python -m scrapers.selftest"""
import asyncio, sys, time
sys.path.insert(0, ".")
from scrapers.registry import build_scrapers, search_all, get_all
from scrapers.base import VulnRecord

QUERY_CVE = "CVE-2024-25641"   # a known CVE (we're testing reachability/parse, not WP-specific)
QUERY_KW = "updraftplus"

async def main():
    scrapers = build_scrapers()
    t0 = time.time()
    recs = await search_all(scrapers, QUERY_CVE)
    print(f"\n=== search_all('{QUERY_CVE}') → {len(recs)} recs in {time.time()-t0:.1f}s ===")
    for r in recs[:12]:
        print(f"[{r.source:9}] {r.cve or r.id:16} sev={r.severity} cvss={r.cvss} "
              f"ranges={len(r.affected)} poc={len(r.poc_refs)} | {r.title[:60]}")
    # per-source counts
    print("\n=== per-source (CVE) ===")
    for s in scrapers:
        try:
            r = await s.get(QUERY_CVE)
            print(f"{s.name:12} get→ {'OK' if r else 'none'}  {('- '+r.title[:50]) if r else ''}")
        except Exception as e:
            print(f"{s.name:12} get→ ERR {type(e).__name__}: {e}")
    print("\n=== keyword search updraftplus (per source) ===")
    for s in scrapers:
        t=time.time()
        try:
            rs = await s.search(QUERY_KW)
            print(f"{s.name:12} {len(rs):3} recs {time.time()-t:.1f}s")
        except Exception as e:
            print(f"{s.name:12} ERR {type(e).__name__}: {e}")
    for s in scrapers:
        await s.close()

asyncio.run(main())
