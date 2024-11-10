# syntax=docker/dockerfile:1

# ----------------------------------------------
# setup stage
# ----------------------------------------------
FROM golang:1.23-alpine AS setup-stage

WORKDIR /app

RUN go env -w GOCACHE=/go-cache
RUN go env -w GOMODCACHE=/gomod-cache

RUN apk --no-cache add \
    sqlite \
    gcc \
    g++ 

COPY cmd ./cmd
COPY pkg ./pkg
COPY go.mod go.sum ./

# ----------------------------------------------
# build stage
# ----------------------------------------------
FROM setup-stage AS build-stage

# Linkmode enabled use on scratch and distroless images
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache \
   go build \
   -o /go-lock \
   -a -ldflags '-linkmode external -extldflags "-static"' \
   cmd/main.go

# ----------------------------------------------
# test stage
# ----------------------------------------------
FROM setup-stage AS test-stage
RUN go test -v ./...

# ----------------------------------------------
# development stage
# ----------------------------------------------
FROM setup-stage AS development-stage

# RUN go install github.com/a-h/templ/cmd/templ@latest
RUN go install github.com/air-verse/air@latest

EXPOSE 8080

CMD ["air", "-c", "third_party/.air.toml"]

# ----------------------------------------------
# production stage
# ----------------------------------------------
FROM gcr.io/distroless/base-debian12 AS production-stage

WORKDIR /

COPY --from=build-stage /go-lock /

EXPOSE 8080

ENTRYPOINT ["/go-lock"]