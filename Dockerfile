# Honeysight: single static Go binary, no cgo (pure-Go SQLite driver).
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/honeysight ./cmd/honeysight

# distroless/static: no shell, no package manager — minimal attack surface,
# which matters for a honeypot. Runs as the built-in nonroot user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/honeysight /usr/local/bin/honeysight
# SQLite DB, auto-generated TLS cert and SSH host key live here.
VOLUME /data
ENV HONEYSIGHT_DATA_DIR=/data
EXPOSE 8080 8443 2222 6380
ENTRYPOINT ["/usr/local/bin/honeysight"]
CMD ["-config", "/etc/honeysight/config.yml"]
