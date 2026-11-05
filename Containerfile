FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build

ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.* ./
COPY cmd/ ./cmd/
RUN go vet ./... && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath -ldflags="-s -w" -o /out/checker ./cmd/checker

FROM docker.io/library/alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63

WORKDIR /app
COPY --from=build /out/checker /app/checker
USER 10001
EXPOSE 8080
ENTRYPOINT ["/app/checker"]