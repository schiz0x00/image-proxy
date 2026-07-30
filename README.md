# image-proxy

[![Go version](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev)
[![Build](https://github.com/schiz0x00/image-proxy/actions/workflows/build.yml/badge.svg)](https://github.com/schiz0x00/image-proxy/actions/workflows/build.yml)
[![License](https://img.shields.io/github/license/schiz0x00/image-proxy)](LICENSE)
[![Release](https://img.shields.io/github/v/release/schiz0x00/image-proxy)](https://github.com/schiz0x00/image-proxy/releases)

Stateless streaming image proxy. Fetches an image URL and streams it back — no cache, no storage, no processing.

## Endpoints

- `GET /image?url=https://example.com/image.png` — proxies the image
- `GET /health` — returns `200 OK`

## Run

```sh
go run .                       # local, listens on :8080
docker build -t image-proxy .  # or in Docker
docker run -p 8080:8080 image-proxy
```

## Releases

Pushing a `v*` or `V*` tag builds static binaries for linux and darwin on amd64 and arm64, and attaches them plus `checksums.txt` to a GitHub release.

## Behavior

- Streams the origin response directly; never buffers the full image.
- Responses capped at 50 MB.
- Only `http`/`https` URLs accepted.
- Origin status code is passed through; origin timeout → 504, other origin failures → 502.
- CORS: `Access-Control-Allow-Origin: *` on all responses.

## Security

- **Origin allowlist**: `ALLOWED_HOSTS` takes a comma-separated list of hostnames; subdomains of each entry are included, and redirect targets are checked too. Unset, any public host may be fetched — which makes the deployment an open relay for traffic laundering, so set it in production.
- **SSRF protection**: Private, loopback, link-local, CGNAT, and benchmark IP ranges are blocked. Hostnames resolving to those ranges are also blocked. Bare local hostnames (`localhost`, `*.local`, `*.internal`) are denied.
- **Redirect validation**: Follows at most 5 redirects; rejects redirects to private IPs or non-http(s) schemes.
- **Rate limiting**: 20 requests/second per client IP (burst 40). Returns 429 when exceeded. Behind a reverse proxy, set `TRUSTED_PROXY_HOPS` to the number of proxies in front of the server so buckets are keyed on the real client instead of collapsing into one. `X-Forwarded-For` is ignored unless that count is set, since clients can forge it.
- **Content-Type enforcement**: Non-image content types from the origin are replaced with `image/jpeg`.
- **Load shedding**: at most 256 concurrent origin fetches (503 with `Retry-After` beyond that), 64 connections per origin host, and a 100,000-entry ceiling on the rate-limiter table. `/health` stays outside the concurrency limit.
- **Error sanitization**: Internal error details are logged server-side only; generic status text is returned to clients.
- **Log redaction**: Query parameters are stripped from URLs before logging.
- **Security headers**: `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, and `Referrer-Policy: no-referrer` on every response, including `/health` and errors. The CSP matters for `image/svg+xml`, which passes the content-type check but can run script when opened directly.
- **Server hardening**: Write timeout (60s), header read timeout (5s), max header size (16 KB).

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `ALLOWED_HOSTS` | unset (any public host) | Comma-separated hostname allowlist; subdomains are included |
| `TRUSTED_PROXY_HOPS` | `0` | Number of reverse proxies in front; enables `X-Forwarded-For` parsing |

## Development

```sh
make test      # go test -race
make lint      # golangci-lint (config in .golangci.yml)
make vet fmt   # go vet / go fmt
make coverage  # writes coverage.html
make build     # local binary
```

`make lint` needs [golangci-lint](https://golangci-lint.run) v2; the config uses the v2 schema and will not load under v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and feature requests welcome via [issues](https://github.com/schiz0x00/image-proxy/issues).

## License

MIT — see [LICENSE](LICENSE).
