# ---- Build stage ----
FROM golang:1.25.4-alpine AS builder
WORKDIR /app

# Cache deps
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binary for linux
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o golock ./cmd/main.go

# ---- Runtime stage ----
# Distroless for Kubernetes (has certificates + minimal attack surface)
FROM gcr.io/distroless/static:nonroot

WORKDIR /app

# Copy binary (web assets are embedded)
COPY --from=builder /app/golock .
COPY --from=builder /app/internal/database/migrations ./internal/database/migrations

# Expose
EXPOSE 8080

# Run as non-root by default
USER nonroot:nonroot

# No shell - must use ENTRYPOINT
ENTRYPOINT ["/app/golock"]
