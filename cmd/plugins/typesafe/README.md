# TypeSafe plugin

Adds TypeSafe System One models (such as Jev) to CLIProxyAPI.

- Clients call `POST /v1/systemone` on the proxy with the usual proxy API key. The body
  is TypeSafe's System One request and is forwarded unchanged.
- The proxy picks a TypeSafe key in rotation. A key that TypeSafe rejects (401/403),
  rate limits (429) or fails on (5xx) is cooled down and the request moves to the next key.
- Each key gets a card under Quota Management (Plugin tab): model count, plus requests
  and tokens sent through the proxy since it last started. TypeSafe's API reports no
  plan, balance or limits, so the card cannot show them.

## Build

Needs cgo (a C compiler on `PATH`).

```bash
go build -buildmode=c-shared -o plugins/windows/amd64/typesafe-v1.0.0.dll ./cmd/plugins/typesafe
```

Use `.so` on Linux and `.dylib` on macOS, under `plugins/<os>/<arch>/`. Then enable it:

```yaml
plugins:
  enabled: true
  configs:
    typesafe:
      enabled: true
```

## Add a key

Save one file per key in the auth directory, for example `auths/typesafe-main.json`:

```json
{"type": "typesafe", "api_key": "YOUR_TYPESAFE_KEY", "label": "Main"}
```

`label` is optional. `base_url` is optional and must be `https`; it defaults to
`https://api.typesafe.ai`. The key is only ever sent to that host.
