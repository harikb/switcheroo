FROM docker.io/golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o switcheroo .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/switcheroo /switcheroo
EXPOSE 4000
ENTRYPOINT ["/switcheroo", "--config", "/etc/switcheroo/switcheroo.yaml"]
