FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o smtp-server .

# Production image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata netcat-openbsd curl

# Create non-root user
RUN adduser -D -s /bin/sh mailuser

WORKDIR /app

# Copy binary
COPY --from=builder /app/smtp-server .

# Create directories
RUN mkdir -p /app/logs /app/certs /tmp/mail
RUN chown -R mailuser:mailuser /app /tmp/mail

USER mailuser

# Expose ports
EXPOSE 25 587 2525

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nc -z localhost ${SMTP_PORT:-25} || exit 1

CMD ["./smtp-server"]