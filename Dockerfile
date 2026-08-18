# Patchlight — minimal production image.
# Build:  docker build -t patchlight .
# Run:    docker run -d -p 127.0.0.1:8425:8425 -v patchlight-data:/data patchlight

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO is required by the mattn/go-sqlite3 driver used in this build.
ARG ISSUER_PUBKEY=""
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.issuerPublicKeyB64=${ISSUER_PUBKEY}" \
    -o /out/patchlight ./cmd/patchlight

FROM debian:bookworm-slim
RUN useradd -r -u 10001 patchlight \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/patchlight /usr/local/bin/patchlight
USER patchlight
VOLUME /data
EXPOSE 8425
ENTRYPOINT ["patchlight", "-listen", "0.0.0.0:8425", "-db", "/data/patchlight.db", "-license", "/data/patchlight-license.key"]
