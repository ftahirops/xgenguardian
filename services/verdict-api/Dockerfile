# syntax=docker/dockerfile:1.7
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/verdict-api ./cmd/verdict-api

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/verdict-api /usr/local/bin/verdict-api
EXPOSE 8080 50051
ENTRYPOINT ["/usr/local/bin/verdict-api"]
