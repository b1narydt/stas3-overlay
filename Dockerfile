FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o stas3-overlay .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/stas3-overlay /usr/local/bin/stas3-overlay
ENTRYPOINT ["stas3-overlay"]
