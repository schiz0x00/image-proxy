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

## Note

The proxy fetches any URL it is given (SSRF surface). Keep it private or add a host allowlist before exposing publicly.
