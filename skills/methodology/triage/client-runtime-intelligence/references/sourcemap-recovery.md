# Source map recovery and secret detection: working pipeline

Field-tested on a 40k-subdomain enterprise target. Recovered 5,013 original source files from 253
maps across 69 applications. Scripts in `../scripts/`.

## Pipeline

```
live hosts
  -> harvest <script src> from each root         (js_urls.txt)
  -> download each bundle, scan with scan_secrets.py
       - records SOURCEMAP_REF findings (the declared .map name)
  -> resolve every SOURCEMAP_REF to an absolute URL  (urljoin against the bundle URL)
  -> fetch each .map, VALIDATE ACROSS WHOLE FILE
  -> maprecover.py: write sourcesContent to disk, drop vendor files
  -> deepsource.py over the recovered tree
```

Delete each `.map` after recovering from it. Maps run to 19 MB; a 1,600-map sweep will fill a disk
otherwise. Add a free-space guard in the fetch worker:

```bash
avail=$(df --output=avail -k / | tail -1)
[ "$avail" -lt 1500000 ] && exit 0
```

## The validation bug, in detail

JSON source maps are emitted with `"mappings"` before `"sources"`. `"mappings"` is base64 VLQ and
scales with bundle size.

Measured on a real 6.4 MB map:

```
total size                 6,456,887 bytes
offset of "sources"        1,423,388
offset of "sourcesContent" 1,475,665
first 160 bytes            {"version":3,"file":"static/js/main.7bc67545.js","mappings":";2BAAAA,EAAOC,..."
```

Any prefix check under ~1.4 MB rejects this map. The failure is silent and **inverts the sweep**:
small maps pass, large application bundles are discarded.

Correct check:

```bash
head -c 200 "$f" | grep -q '"version"'   || { rm -f "$f"; exit 0; }
grep -qF '"sources"'        "$f"          || { rm -f "$f"; exit 0; }
grep -qF '"sourcesContent"' "$f" && hc=1
```

Before/after on the same 1,597 candidate URLs:

| | maps validated | files recovered | hosts |
|---|---|---|---|
| prefix check (broken) | 197 | 2,047 | 41 |
| whole-file check | 253 | 5,013 | 69 |

Detection heuristic: if a host demonstrably serves a large map and never appears in your recovery
output, you have this bug.

## Vendor filtering

`node_modules` alone is insufficient. Builds inline dependencies fetched by URL:

```
recovered/host/https_/raw.githubusercontent.com/nevware21/ts-utils/refs/tags/0.12.5/lib/src/...
```

Those pass a `node_modules` filter and inflate "first-party" counts by an order of magnitude. On one
app: 237 sources survived the `node_modules` filter, but only 154 were genuinely first-party, and
the rest were vendored-by-URL libraries.

Exclude: `node_modules`, `webpack/bootstrap`, `webpack/runtime`, `/~/`, `core-js`,
`regenerator-runtime`, and any path containing an embedded `http`/`https` host.

## deepsource.py — why it exists

`scan_secrets.py` (regex bank, 67 rules) scored **zero** on this file:

```js
const getGameClientSecret = () => {
  if (window.location.host.includes('prod')) {
    return "6yHPi11xK2LNGtgboMXhsJozojyg9cZh64vMoTj6Qrc="
  }
  return "EGuGP2380DwpWWLyJRiS9DpqOanJ13EmX3PQ8zeTdwM="
}
```

No assignment, so no pattern matches. `deepsource.py` catches it two ways:

- `SECRET_NAME` matches `clientsecret` in the arrow-function name, then reports literals in the
  following 6 lines.
- the entropy pass reports both base64 strings on length + Shannon entropy + mixed classes.

Tuning that held up on 5,013 files:

```python
len(lit) >= 16
entropy(lit) >= 3.4
character classes >= 2 of [a-z] [A-Z] [0-9]
reject: camelCase, kebab/snake, file paths, MIME types, *Component/*Module/*Service
```

Yield: 48 named hits + 2,082 entropy hits -> filtered to literals >= 32 chars -> **6 strings**, of
which 2 were real credentials and 4 were `SpecifyYourOwnValue...` placeholders.

## Triage of what comes back

Rank by what the file is, not by rule name:

1. config modules (`constants`, `environment`, `env`, `config`) — base URLs, tenant IDs, client IDs
2. API layers (`axiosInstance`, `api.ts`, `*BackendCalls*`) — endpoint surface + auth attachment
3. route tables — hidden/debug routes, hostname-allowlist gating
4. interceptors/guards — client-side-only authorization

Then validate every candidate credential against its issuer before writing a report. See the
"Validate every recovered credential" section in `../SKILL.md`.

## Known false-positive classes

Seen repeatedly, all cost real triage time:

| Hit | Reality |
|---|---|
| `AWS_ACCESS_KEY_ID` on `ABIA...` | base64 **font data**; restrict the rule to `AKIA`/`ASIA` |
| `PRIVATE_KEY` on `-----BEGIN PRIVATE KEY-----` | the `jose` library's PKCS#8 **format check string**; require 40+ chars of base64 body after the header |
| `password:"password"` | Angular form-control name |
| `PASSWORD:"/change-password"` | route constant |
| `password:"[type=password]"` | CSS selector |
| `client_secret:"your-client-secret"` | placeholder |

Add a noise filter for `example|sample|dummy|placeholder|your[_-]?key|xxxx+|changeme|\$\{...\}` on
the generic rules only. Never on the vendor-prefixed rules (`AKIA`, `sk-ant-`, `ghp_`), which are
specific enough to stand alone.
