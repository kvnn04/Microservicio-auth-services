# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/api ./cmd/api && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/worker ./cmd/worker
FROM gcr.io/distroless/static-debian12
COPY --from=build /bin/api /api
COPY --from=build /bin/worker /worker
EXPOSE 8080
ENTRYPOINT ["/api"]
