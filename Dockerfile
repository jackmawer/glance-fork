# Build on the native platform and cross-compile for the target one, rather than
# running the whole toolchain under emulation for each platform being published.
FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine3.24 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app
COPY . /app
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build .

FROM alpine:3.24

WORKDIR /app
COPY --from=builder /app/glance .

EXPOSE 8080/tcp
ENTRYPOINT ["/app/glance", "--config", "/app/config/glance.yml"]
