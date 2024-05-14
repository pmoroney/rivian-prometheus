FROM golang:1.22

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . ./
RUN go build -v -o rivian-prometheus

CMD ["/app/rivian-prometheus"]
