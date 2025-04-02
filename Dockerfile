FROM golang:1.23-alpine

RUN apk add --no-cache git openssl

WORKDIR /app

# Копируем ВСЕ файлы проекта (включая proxy/demoCA)
COPY . .

RUN go build -o proxy-server

EXPOSE 8080

CMD ["./proxy-server"]