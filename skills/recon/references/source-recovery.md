# Source map recovery

Read this when a `.js.map` returns 200 with a `sourcesContent` array.

Two separate outcomes follow, and both matter:

1. **The exposure itself is a Low finding.** Write it up.
2. **The recovered source is recon.** It replaces every minute you would have spent on minified bundles.

---

## Step 1: harvest every map

Collect the bundle list from the browser's network log, not from the HTML alone; lazily loaded chunks only appear after navigating into a feature.

```bash
# from a list of bundle URLs in bundles.txt
mkdir -p source-code/_maps
while read -r u; do
  m="${u%%\?*}.map"
  out="source-code/_maps/$(basename "${m}")"
  curl -sS --compressed -o "$out" -w '%{http_code} %{size_download} '"$m"'\n' "$m"
done < bundles.txt
```

Anything under a few hundred bytes is an error page; delete it. Keep going until every bundle has been tried, including the CSS ones and the vendor chunk.

## Step 2: unpack into `source-code/`

```python
import json, pathlib, re, sys

OUT = pathlib.Path("source-code")

def unpack(map_path):
    data = json.loads(pathlib.Path(map_path).read_text(encoding="utf-8", errors="replace"))
    srcs, contents = data.get("sources", []), data.get("sourcesContent") or []
    written = 0
    for src, body in zip(srcs, contents):
        if body is None:
            continue
        if "node_modules" in src or src.startswith("webpack/"):
            continue
        rel = re.sub(r"^(webpack://|webpack-internal://|/)+", "", src)
        rel = re.sub(r"[?*:<>|\"]", "_", rel).lstrip("./")
        dest = OUT / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(body, encoding="utf-8")
        written += 1
    return written

total = sum(unpack(p) for p in sys.argv[1:])
print(f"{total} files written under {OUT}")
```

Notes that matter on Windows: strip the `webpack://` prefix, sanitise `?*:<>|"` out of paths, and drop leading slashes or `pathlib` will write to the drive root. Skip `node_modules` unless a specific dependency is under suspicion; it triples the tree for no gain.

## Step 3: fan agents over the tree, not over the bundles

Count the files first, then decide the split. Group by feature directory, never by file count alone, so each agent sees a coherent slice.

```bash
find source-code -type f \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' -o -name '*.vue' \) | wc -l
find source-code -maxdepth 3 -type d | head -60
```

Brief each agent with: the directory it owns, the target and scope line from `prompt.md`, the browser rule from `CLAUDE.md` verbatim, and this ask:

> Read every file in your directory line by line. Report, with `path:line` for each: every server endpoint referenced including ones no UI element calls; every authorization check performed in the client; every feature flag, role name, permission string and internal route; every sink (`innerHTML`, `dangerouslySetInnerHTML`, `eval`, `Function`, `document.write`, template compilation, `location` assignment, `window.open`); every `postMessage` sender and listener with its origin check or lack of one; every validation regex verbatim; every hardcoded key, bucket, host or token; every TODO or comment admitting a known gap. Do not test anything. Do not open a browser. Return findings as a list, one line each, with a one-sentence hypothesis per item.

Then merge the returns into `js-inventory.md` and push every discovered endpoint into `state.csv` as `pending`.

## Step 4: what recovered source is uniquely good for

- **Client-side-only authorization.** A `disabled={!hasAccessToScope}` or a route guard with no server twin is a direct test case, and this exact pattern produced a confirmed High on a past target.
- **Endpoints the UI never calls.** Admin routes, internal routes, deprecated-but-live versions.
- **Validation regexes.** Extract each one verbatim and execute it locally against bypass candidates. This proves a bypass with no session at all and survives lockouts and WAF blocks.
- **The permission model.** Role names and permission strings give you the exact vocabulary for mass-assignment attempts.
- **Ruling classes out cheaply.** Reading the real HTML renderer or the real URL validator closes whole columns of the matrix with evidence instead of guesswork.

## Step 5: the report

Source map exposure is a **Low**. Keep it short and factual: the URL that returns the map, the file count recovered, one or two path names that show it is first-party application source rather than a vendor bundle, and the one-line fix (stop shipping maps to production, or serve them only to authenticated internal users).

Do not inflate it and do not attach the recovered tree. Do not claim it leads to anything unless a separate confirmed finding actually came out of it, in which case that is its own report and the map exposure stays independent.

If the map is exposed but `sourcesContent` is null and only the mappings exist, say so; that is weaker and usually not worth filing.
