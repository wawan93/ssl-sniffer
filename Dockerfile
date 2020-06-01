FROM golang:alpine
RUN apk add --update gcc libc-dev libpcap-dev curl

WORKDIR /app

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY . .
RUN CGO_LDFLAGS="-Wl,-static -L/usr/lib/x86_64-linux-gnu/libpcap.a -lpcap -Wl,-Bdynamic" go build -o sniffer ./cmd/cli/main.go

CMD ["/app/sniffer"]
