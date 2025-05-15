# Stage 1: Build the Go binary
FROM golang:latest AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker's caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the rest of the source code
COPY . ./

# Build the Go binary
RUN go build -v -o rivian-prometheus

# Stage 2: Create a minimal image with the compiled binary
FROM debian:stable-slim

WORKDIR /app

# Install CA certificates
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /app/rivian-prometheus /app/rivian-prometheus

# Expose the port your application listens on
EXPOSE 9666

# Command to run the application
CMD ["/app/rivian-prometheus"]
