FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY src/device-server/go.mod src/device-server/go.sum ./
RUN go mod download
COPY src/device-server/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/device-server ./cmd/device-server && \
    CGO_ENABLED=0 go build -trimpath -o /out/device-migrate ./cmd/device-migrate && \
    CGO_ENABLED=0 go build -trimpath -o /out/device-bootstrap ./cmd/device-bootstrap && \
    CGO_ENABLED=0 go build -trimpath -o /out/device-admin ./cmd/device-admin

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN addgroup -S -g 65532 peerloom && adduser -S -D -H -u 65532 -G peerloom peerloom
COPY --from=build /out/ /usr/local/bin/
COPY infra/migrations/ /app/infra/migrations/
USER 65532:65532
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["device-server"]
