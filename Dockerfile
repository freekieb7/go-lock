FROM golang:1.21-alpine

ENV CGO_ENABLED=1

RUN apk --no-cache add \
    sqlite \
    gcc \
    g++ \
    redis

RUN redis-server --daemonize yes

WORKDIR /app

COPY . .

RUN go install github.com/cosmtrek/air@latest
RUN go install github.com/go-delve/delve/cmd/dlv@latest

RUN go mod download

CMD ["air", "-c", ".air.toml"]