# image-proxy

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

## Behavior

- Streams the origin response directly; never buffers the full image.
- Responses capped at 50 MB.
- Only `http`/`https` URLs accepted.
- Origin status code is passed through; origin timeout → 504, other origin failures → 502.
- CORS: `Access-Control-Allow-Origin: *` on all responses.

## Security

- **SSRF protection**: Private, loopback, link-local, CGNAT, and benchmark IP ranges are blocked. Hostnames resolving to those ranges are also blocked. Bare local hostnames (`localhost`, `*.local`, `*.internal`) are denied.
- **Redirect validation**: Follows at most 5 redirects; rejects redirects to private IPs or non-http(s) schemes.
- **Rate limiting**: 20 requests/second per client IP (burst 40). Returns 429 when exceeded.
- **Content-Type enforcement**: Non-image content types from the origin are replaced with `image/jpeg`.
- **Error sanitization**: Internal error details are logged server-side only; generic status text is returned to clients.
- **Log redaction**: Query parameters are stripped from URLs before logging.
- **Security headers**: `X-Content-Type-Options: nosniff` set on all responses.
- **Server hardening**: Write timeout (60s), header read timeout (5s), max header size (16 KB).
