package main

import (
	"Web_Security_HW/cert"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	caCert     tls.Certificate
	baseDir    = "." // Базовая директория проекта
	caCertPath = filepath.Join(baseDir, "demoCA", "cacert.pem")
	caKeyPath  = filepath.Join(baseDir, "demoCA", "private", "cakey.pem")
	crlPath    = filepath.Join(baseDir, "demoCA", "crl", "crl.pem")
)

func main() {
	var err error

	// Загрузка CA сертификата и ключа
	caCert, err = tls.LoadX509KeyPair(caCertPath, caKeyPath)
	if err != nil {
		log.Fatalf("Ошибка загрузки CA сертификата: %v\nПроверьте пути:\nCA cert: %s\nCA key: %s",
			err, caCertPath, caKeyPath)
	}

	// Проверка существования CRL
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		log.Printf("Внимание: файл CRL не найден по пути %s", crlPath)
	}

	server := &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(handleRequest),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Printf("Прокси-сервер запущен на :8080\nКонфигурация:\nCA cert: %s\nCA key: %s\nCRL: %s",
		caCertPath, caKeyPath, crlPath)
	log.Fatal(server.ListenAndServe())
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/crl.pem" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		http.ServeFile(w, r, crlPath)
		return
	}

	if r.Method == http.MethodConnect {
		handleHTTPS(w, r)
	} else {
		handleHTTP(w, r)
	}
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("HTTP %s %s", r.Method, r.URL)

	r.Header.Del("Proxy-Connection")
	r.RequestURI = "" // Необходимо для корректного форвардинга

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("Ошибка при выполнении запроса: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Копируем заголовки ответа
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("Ошибка при копировании тела ответа: %v", err)
	}
}

func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	domain := strings.Split(host, ":")[0]

	// Передаём caCert в GenerateCertificate
	cert, err := cert.GenerateCertificate(domain, caCert)
	if err != nil {
		log.Printf("Failed to generate cert for %s: %v", domain, err)
		http.Error(w, "Certificate generation failed", http.StatusInternalServerError)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijacking failed", http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Printf("Failed to send CONNECT response: %v", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert}, // Используем сгенерированный сертификат
		MinVersion:   tls.VersionTLS12,
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	targetConn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		log.Printf("Failed to connect to target: %v", err)
		return
	}
	defer targetConn.Close()

	errChan := make(chan error, 1)
	go func() {
		_, err := io.Copy(targetConn, tlsConn)
		errChan <- err
	}()

	_, err = io.Copy(tlsConn, targetConn)
	if err != nil && err != io.EOF {
		log.Printf("Copy error: %v", err)
	}

	<-errChan
}
