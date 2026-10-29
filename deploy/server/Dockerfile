# 仅预编译服务端包；构建上下文是解压后的包根，无源码或编译工具链。
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN addgroup -S -g 65532 peerloom && adduser -S -D -H -u 65532 -G peerloom peerloom
COPY bin/ /usr/local/bin/
COPY infra/migrations/ /app/infra/migrations/
USER 65532:65532
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["device-server"]
