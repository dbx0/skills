---
name: gateway-layer-attribution
description: Determine WHICH layer answered an API request — the gateway (Kong/Envoy/APISIX/AWS API GW) or the upstream application — before concluding a route is protected, absent, or vulnerable. Use when testing APIs behind a gateway, when a 401/403/404 needs interpreting, when auth appears inconsistent across routes on one host, or before fuzzing paths on a gateway-fronted API.
---

# Gateway-layer attribution

Every response from a gateway-fronted API was written by one of two things: the **gateway** or the
**upstream app**. Almost all API testing mistakes come from not knowing which. A `404` from the
gateway means the route does not exist. A `404` from the app means it does, and you reached it.
Those lead to opposite conclusions, and they look identical if you only read the status code.

**Attribute the layer first. Then interpret.**

## The three states of a route

On a gateway, a path is in exactly one of three states. Telling them apart *is* the auth audit:

| State | Signature | Meaning |
|---|---|---|
| **No route** | gateway's own error body, no upstream timing header | path not registered; fuzzing it is wasted |
| **Route + auth plugin** | gateway's auth error (`no jwt token`, `no API key found`) | correctly protected |
| **Route, NO auth plugin** | *application* response (even a 4xx) + upstream timing header | **the finding** — anonymous traffic reaches the app |

Real captures from an authorized engagement, one host, one prefix:

```
/ap-self-service/v1/users/me         401  {"message": "no jwt token"}    ← Kong. plugin PRESENT
/ap-self-service/v1/taxonomy?…       200  {…"cpc_min"…}                  ← app.  plugin ABSENT
/ap-self-service/zzz-control-9182    404  {"message":"no Route matched"} ← Kong. no route
```

The `401` is what makes the `200` a vulnerability rather than a public API: the same prefix, the
same gateway, one route configured and its neighbour not. **Always pair a suspected-ungated route
with a known-gated route on the same prefix** — that control is the difference between "missing
access control" and "this endpoint is intentionally public," and a triager will ask for it.

## Layer signatures

**Gateway-authored bodies** are terse, uniform, and mention routing or plugins:

| Body / header | Layer | Product |
|---|---|---|
| `{"message":"no Route matched with those values"}` | gateway | Kong |
| `{"message":"no jwt token"}` / `"no API key found in request"` | gateway | Kong auth plugin |
| `upstream connect error…` / `no healthy upstream` | gateway | Envoy / Istio |
| `{"message":"Missing Authentication Token"}` | gateway | **AWS API Gateway — this means 404, not auth** |
| `{"message":"Forbidden"}` bare | gateway | AWS API GW (bad key / no route) |
| RFC-7807 JSON, field-level validation, stack hints, app error codes | **app** | you got through |

**Timing headers are the strongest tell** — the gateway only emits them when it actually proxied
somewhere:

```
x-kong-upstream-latency:  <ms>   ← Kong forwarded upstream. PRESENT = you reached the app
x-kong-proxy-latency:     <ms>   ← Kong's own overhead (present even when it answers itself)
x-envoy-upstream-service-time    ← Envoy forwarded upstream
```

`x-kong-upstream-latency` **present** on an unauthenticated request is the cleanest possible proof
the request left the gateway. `x-kong-proxy-latency` alone, with no upstream header, means Kong
answered it itself.

Other discriminators when headers are stripped: **response timing** (gateway-authored errors return
in single-digit ms; upstream round-trips are visibly slower), body byte-size stability (gateway
errors are identical to the byte across paths), and `Server`/`Via` headers.

## An application 400 is a SUCCESS signal

The counter-intuitive rule, and the one worth internalizing:

> A `400`, `422`, or `500` **from the application** proves the gateway forwarded you. It is evidence
> of reach, not of rejection.

Failing to see this costs findings. Testing an ungated route with incomplete parameters returned
`400` and `500`; read as failure, it nearly retracted a valid report. The route was ungated the
whole time — the app was simply rejecting malformed input, which only an app that *received the
request* can do. Supply the required parameters and the same route returns `200` with data.

**So: when an unauthenticated request yields an app-layer `400`, do not stop.** Recover the real
parameter set (client bundle, OpenAPI, `_buildManifest`, mobile app) and retry. The auth bypass is
already proven; you are only working on the impact.

## Procedure

1. **Establish the two controls on the target prefix**, in the same run:
   - a nonsense path (`/prefix/zzz-control-<rand>`) → learn the gateway's no-route signature
   - a known-protected route → learn the gateway's auth-plugin signature
2. **Probe each candidate route unauthenticated**, capturing full headers (`curl -si --compressed`).
3. **Attribute** each response: gateway no-route / gateway auth / app.
4. Anything landing in **app** without credentials is an ungated route. Confirm with the timing
   header, then pursue impact.
5. **Re-run the controls at the end.** If the no-route control has changed shape, the gateway config
   or your egress moved and the batch needs re-running ([[egress-waf-evasion]] Step 0).

```bash
attr () { # attr <url> — print status + layer verdict
  h=$(curl -si --compressed -m 20 "$1")
  s=$(printf '%s' "$h" | head -1 | awk '{print $2}')
  if printf '%s' "$h" | grep -qi '^x-kong-upstream-latency\|^x-envoy-upstream-service-time'; then v=APP
  elif printf '%s' "$h" | grep -qi 'no Route matched\|Missing Authentication Token'; then v=GW-NOROUTE
  elif printf '%s' "$h" | grep -qi 'no jwt token\|no API key found'; then v=GW-AUTH
  else v=UNKNOWN-read-body; fi
  printf '%-58s %s  %s\n' "$1" "$s" "$v"
}
```

## Why this beats fuzzing

Gateways answer non-routes cheaply and uniformly, so a wordlist against a gateway-fronted host
mostly measures the gateway. One engagement burned ~51,000 requests on a gateway-fronted host for
**zero** routes; a sibling host gave up **57** routes by reading them out of the front-end bundle.
**Recover the client's route list, then attribute each route.** Fuzz only after that is exhausted.

## Anti-patterns

- Reading `404` as "not there" without checking whether the *gateway* or the *app* wrote it.
- Reading an app-layer `400`/`500` as "blocked" and moving on — it is proof of reach.
- Reporting an ungated route with no gated sibling as control; triage will call it an intentional
  public endpoint, and without the control they are right to.
- Treating AWS API Gateway's `Missing Authentication Token` as an auth finding. It is that
  product's 404.
- Concluding "the API requires auth" from one protected route. Plugin config is **per-route**;
  the whole point is that it is applied inconsistently.
