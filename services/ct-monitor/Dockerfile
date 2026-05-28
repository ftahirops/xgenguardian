# syntax=docker/dockerfile:1.7
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/ct-monitor ./cmd/ct-monitor

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/ct-monitor /usr/local/bin/ct-monitor
ENTRYPOINT ["/usr/local/bin/ct-monitor"]
