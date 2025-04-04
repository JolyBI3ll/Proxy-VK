FROM golang:1.24-alpine

RUN apk add --no-cache git openssl ca-certificates

COPY ./proxy/demoCA /app/proxy/demoCA

COPY ./proxy/demoCA/cacert.pem /usr/local/share/ca-certificates/my-ca.crt
RUN update-ca-certificates

WORKDIR /app
COPY . .

RUN go mod download && go build -o proxy-server

EXPOSE 8080
CMD ["./proxy-server"]