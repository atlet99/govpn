# Dockerfile for GoVPN server
FROM golang:1.24.2-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    openssl \
    build-base

# Create working directory
WORKDIR /app

# Copy go.mod and go.sum for dependency caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build GoVPN server
RUN CGO_ENABLED=0 go build \
    -a -installsuffix cgo \
    -o govpn-server \
    ./cmd/server

# Production image
FROM alpine:latest

# Install required packages
RUN apk add --no-cache \
    ca-certificates \
    openssl \
    curl \
    iptables \
    iproute2 \
    tini

# Create govpn user
RUN addgroup -g 1000 govpn && \
    adduser -D -s /bin/sh -u 1000 -G govpn govpn

# Create necessary directories
RUN mkdir -p /etc/govpn /var/log/govpn /var/lib/govpn /etc/govpn/certs
RUN chown -R govpn:govpn /etc/govpn /var/log/govpn /var/lib/govpn

# Copy binary file
COPY --from=builder /app/govpn-server /usr/local/bin/govpn-server
RUN chmod +x /usr/local/bin/govpn-server

# Copy configuration files
COPY docker/configs/ /etc/govpn/

# Copy scripts
COPY docker/scripts/ /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh

# Expose ports
EXPOSE 1194/udp 8080/tcp 9090/tcp

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# For VPN server we need root privileges
# USER govpn

# Use tini as init process
ENTRYPOINT ["/sbin/tini", "--"]

# Default command
CMD ["/usr/local/bin/start-govpn.sh"] 