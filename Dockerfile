FROM golang:1.26-alpine AS builder

WORKDIR /build
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o image-proxy .

# distroless static: CA certs included, runs as non-root
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /build/image-proxy /image-proxy

EXPOSE 8080

ENTRYPOINT ["/image-proxy"]
