# Stage 1: Build the Go application
FROM golang:1.21-alpine AS builder

# Install build dependencies for go-sqlite3
RUN apk add --no-cache gcc libc-dev sqlite-dev

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./
# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download
RUN go mod verify # Good practice

# Copy the source code
COPY . .

# Build the application
# CGO_ENABLED=1 is required for go-sqlite3
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o main .

# Stage 2: Create the final image
FROM alpine:latest

# For go-sqlite3, the final image might need libsqlite3 if not statically linked,
# but common practice is to build statically or ensure it's available.
# Alpine base image usually has it or it's small to add.
# Let's ensure ca-certificates is there.

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/main .

# The 'uploads' directory will be managed by a volume mount defined in docker-compose.yml
# and created by the Go application if it doesn't exist at runtime.

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./main"]
