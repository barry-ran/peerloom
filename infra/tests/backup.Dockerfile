# Test-only image: no ports are published, no host data/secret directory is mounted.
FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS migrate
WORKDIR /src
COPY src/device-server/go.mod src/device-server/go.sum ./
RUN go mod download
COPY src/device-server/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/device-migrate ./cmd/device-migrate

FROM postgres:18.6-alpine3.24@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5
# Official stable Alpine branch, exact Python package; no testing/edge/custom mirror.
# Preserve the fully resolved APK versions as image evidence, including transitive dependencies.
RUN printf '%s\n' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main' > /etc/apk/repositories && \
    apk add --no-cache 'python3=3.14.10-r1' && \
    mkdir -p /usr/local/share/peerloom-validation && \
    apk info -vv | sort > /usr/local/share/peerloom-validation/apk-versions.txt && \
    python3 --version > /usr/local/share/peerloom-validation/python-version.txt && \
    pg_dump --version > /usr/local/share/peerloom-validation/postgres-version.txt
COPY --from=migrate /out/device-migrate /usr/local/bin/device-migrate
COPY scripts/postgres-backup.py scripts/test-postgres-backup.py scripts/test-backup-cluster.py scripts/test-backup-container.sh /repo/scripts/
COPY infra/migrations/ /repo/infra/migrations/
USER postgres
WORKDIR /repo
ENV PEERLOOM_TEST_MIGRATE_BIN=/usr/local/bin/device-migrate
ENTRYPOINT ["python3", "/repo/scripts/test-backup-cluster.py", "--run-isolated"]
