# Multi-stage build for phillet-wallet-core
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o phillet-wallet-core ./cmd

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1001 -S wallet && \
    adduser -u 1001 -S wallet -G wallet

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/phillet-wallet-core .

# Change ownership to non-root user
RUN chown -R wallet:wallet /app

# Switch to non-root user
USER wallet

# Expose gRPC port
EXPOSE 50051

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:50051/health || exit 1

# Run the application
CMD ["./phillet-wallet-core"] 