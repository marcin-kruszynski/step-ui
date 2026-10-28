FROM golang:1.21-bookworm AS builder

# Install step CLI and build dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    sqlite3 \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -L https://github.com/smallstep/cli/releases/latest/download/step_linux_amd64.tar.gz | tar xz -C /tmp && \
    cp /tmp/step_linux_amd64/bin/step /usr/local/bin/step && \
    chmod +x /usr/local/bin/step

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod ./
COPY go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Tidy modules and build
RUN go mod tidy
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o main ./cmd

# Final stage
FROM debian:bookworm-slim

# Install step CLI and openssl
RUN apt-get update && apt-get install -y \
    curl \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -L https://github.com/smallstep/cli/releases/latest/download/step_linux_amd64.tar.gz | tar xz -C /tmp && \
    cp /tmp/step_linux_amd64/bin/step /usr/local/bin/step && \
    chmod +x /usr/local/bin/step

# Create app user
RUN useradd -m -s /bin/bash appuser

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/main .

# Create data directory
RUN mkdir -p /app/data && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Run the application
CMD ["./main"]
