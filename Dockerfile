# Stage 1: Build
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o union-svc ./cmd/union-svc

# Stage 2: Runtime
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /build/union-svc .
EXPOSE 8001
ENTRYPOINT ["./union-svc"]
CMD ["--config", "/app/config.yaml"]
