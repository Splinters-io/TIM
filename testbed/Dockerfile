# Build context is the repo root (see docker-compose.yml). Produces one small
# image holding tim, tim-gen and tim-device.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/tim ./cmd/tim \
 && CGO_ENABLED=0 go build -trimpath -o /out/tim-gen ./testbed/gen \
 && CGO_ENABLED=0 go build -trimpath -o /out/tim-device ./testbed/device

FROM alpine:3.20
COPY --from=build /out/ /usr/local/bin/
# The testbed runs as root so `tim serve --std-ports` can bind port 123.
CMD ["tim"]
