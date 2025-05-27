# Use the official Golang image to build your application
FROM golang:1.22-alpine AS builder

# Install git (needed for some Go modules)
RUN apk add --no-cache git

# Set the working directory
WORKDIR /app

# Copy the Go module files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o main .

# Use a minimal base image for the final stage
FROM alpine:latest

# Install ca-certificates for HTTPS/TLS communication
RUN apk --no-cache add ca-certificates tzdata

# Create a non-root user
RUN adduser -D -s /bin/sh appuser

# Set the working directory
WORKDIR /app

# Copy the compiled application from the builder stage
COPY --from=builder /app/main .

# Change ownership to the non-root user
RUN chown appuser:appuser /app/main

# Switch to the non-root user
USER appuser

# Expose the SMTP ports
EXPOSE 2525 25 587 465

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nc -z localhost 2525 || exit 1

# Command to run the executable
CMD ["./main"]