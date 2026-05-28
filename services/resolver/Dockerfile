# syntax=docker/dockerfile:1.7
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/resolver ./cmd/resolver

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/resolver /usr/local/bin/resolver
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/resolver"]
