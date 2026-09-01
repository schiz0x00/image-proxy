FROM golang:1.27-alpine AS builder

WORKDIR /build
# Listing sources explicitly meant a new .go file was silently left out of
# the image. .dockerignore keeps the context to go.mod and the sources.
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o image-proxy .

# distroless static: CA certs included, runs as non-root
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /build/image-proxy /image-proxy

EXPOSE 8080

ENTRYPOINT ["/image-proxy"]
