// client.go
// Lab 9 — Combined Client (Parts C, F + cert generator)
// Run modes:
//   go run client.go load      → Part C: 100 concurrent clients → server on :8080
//   go run client.go tls       → Part F: single TLS client → server on :8443
//   go run client.go gencert   → Part F: generate self-signed cert.pem + key.pem

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	SERVER_ADDR  = "127.0.0.1:8080"
	TLS_ADDR     = "127.0.0.1:8443"
	NUM_CLIENTS  = 100
	DIAL_TIMEOUT = 3 * time.Second
	READ_TIMEOUT = 3 * time.Second
)

// ─── Part C: Load Generator ───────────────────────────────────────────────────

func sendMessage(id int, wg *sync.WaitGroup) {
	defer wg.Done()

	conn, err := net.DialTimeout("tcp", SERVER_ADDR, DIAL_TIMEOUT)
	if err != nil {
		fmt.Printf("[Client %3d] Connection failed: %v\n", id, err)
		return
	}
	defer conn.Close()

	msg := fmt.Sprintf("Hello from client %d", id)
	_, err = conn.Write([]byte(msg))
	if err != nil {
		fmt.Printf("[Client %3d] Write error: %v\n", id, err)
		return
	}

	conn.SetReadDeadline(time.Now().Add(READ_TIMEOUT))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("[Client %3d] Read error: %v\n", id, err)
		return
	}

	fmt.Printf("[Client %3d] Server replied: %s", id, string(buf[:n]))
}

func runLoad() {
	var wg sync.WaitGroup
	start := time.Now()

	fmt.Printf("Launching %d concurrent clients → %s\n\n", NUM_CLIENTS, SERVER_ADDR)

	for i := 1; i <= NUM_CLIENTS; i++ {
		wg.Add(1)
		go sendMessage(i, &wg)
	}

	wg.Wait()
	fmt.Printf("\nAll %d clients done in %v\n", NUM_CLIENTS, time.Since(start))
}

// ─── Part F: TLS Client ───────────────────────────────────────────────────────

func runTLSClient() {
	config := &tls.Config{
		InsecureSkipVerify: true, // OK for self-signed lab cert; never use in production
	}

	conn, err := tls.Dial("tcp", TLS_ADDR, config)
	if err != nil {
		fmt.Println("Failed to connect:", err)
		fmt.Println("Is the TLS server running? go run server.go tls")
		return
	}
	defer conn.Close()

	// Print TLS handshake details
	state := conn.ConnectionState()
	fmt.Println("=== TLS Handshake Info ===")
	fmt.Printf("  TLS Version  : 0x%04x\n", state.Version)
	fmt.Printf("  Cipher Suite : %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("  Resumed      : %v\n", state.DidResume)
	fmt.Println()

	conn.Write([]byte("Hello over TLS!"))

	conn.SetReadDeadline(time.Now().Add(READ_TIMEOUT))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Read error:", err)
		return
	}

	fmt.Println("Server:", string(buf[:n]))
}

// ─── Part F: Cert Generator ───────────────────────────────────────────────────

func runGenCert() {
	// Generate EC private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("Failed to generate key:", err)
		return
	}

	// Certificate template (valid for 1 year, localhost)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Lab9 Self-Signed"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		fmt.Println("Failed to create certificate:", err)
		return
	}

	// Write cert.pem
	cf, _ := os.Create("cert.pem")
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	// Write key.pem
	kf, _ := os.Create("key.pem")
	keyBytes, _ := x509.MarshalECPrivateKey(key)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	kf.Close()

	fmt.Println("Generated cert.pem and key.pem successfully.")
	fmt.Println("Now run: go run server.go tls")
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	mode := "load"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	switch mode {
	case "load":
		runLoad()
	case "tls":
		runTLSClient()
	case "gencert":
		runGenCert()
	default:
		fmt.Println("Usage: go run client.go [load|tls|gencert]")
		fmt.Println()
		fmt.Println("  load     → Part C: 100 concurrent clients → :8080")
		fmt.Println("  tls      → Part F: single TLS client → :8443")
		fmt.Println("  gencert  → Part F: generate cert.pem + key.pem for TLS server")
	}
}
