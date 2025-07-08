FROM golang:1.24.1-alpine as builder 

RUN apk --no-cache add ca-certificates gcc g++ libc-dev

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o ./bin/main ./cmd/main/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates 

COPY --from=builder /app/bin/main /main
COPY --from=builder /app/migrations/ /migrations/
COPY --from=builder /app/.env /.env

CMD ["/main"]