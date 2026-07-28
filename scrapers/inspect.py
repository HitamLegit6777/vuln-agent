"""Deep inspect: per-source get(cve) → print full fields for AI-grounding check."""
import asyncio, sys, json
sys.path.insert(0, ".")
from scrapers.registry import build_scrapers, search_all, _dedupe

CVE = sys.argv[1] if len(sys.argv) > 1 else "CVE-2024-25641"

async def main():
    scrapers = build_scrapers()
    print(f"##### CVE {CVE} — per-source detail #####\n")
    for s in scrapers:
        try:
            r = await s.get(CVE)
        except Exception as e:
            print(f"--- {s.name}: ERR {type(e).__name__}: {e}\n"); continue
        if not r:
            print(f"--- {s.name}: (none)\n"); continue
        print(f"--- {s.name} ---")
        print(f"cve={r.cve!r}  id={r.id!r}")
        print(f"severity={r.severity!r}  cvss={r.cvss!r}  published={r.published!r}")
        print(f"title={r.title!r}")
        print(f"url={r.url!r}")
        print(f"affected_ranges={len(r.affected)}:")
        for a in r.affected:
            print(f"    {a.product!r} eco={a.ecosystem!r} min={a.min_inclusive!r} "
                  f"max_inc={a.max_inclusive!r} max_exc={a.max_exclusive!r} fixed={a.fixed!r}")
        print(f"poc_refs={json.dumps(r.poc_refs, indent=0)[:400]}")
        print(f"diff_patch={r.diff_patch!r}")
        print(f"description(len={len(r.description)}):\n{r.description[:600]}")
        print(f"raw.keys={list(r.raw.keys())}  refs={(r.raw.get('refs') or [])[:5]}")
        # vulnerable check
        print(f"is_vulnerable(None)={r.is_vulnerable(None)}")
        print()
    # dedupe behavior
    print("##### dedupe test #####")
    recs = []
    for s in scrapers:
        try:
            r = await s.get(CVE)
            if r: recs.append(r)
        except Exception: pass
    print(f"before dedupe: {len(recs)} recs, cves={[repr(r.cve) for r in recs]}")
    ded = _dedupe(recs)
    print(f"after dedupe:  {len(ded)} recs, cves={[repr(r.cve) for r in ded]}")
    for s in scrapers: await s.close()

asyncio.run(main())
