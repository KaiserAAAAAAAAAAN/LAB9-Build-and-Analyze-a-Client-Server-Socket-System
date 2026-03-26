package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	HOST         = "127.0.0.1"
	PORT         = "8080"
	CONN_TIMEOUT = 10 * time.Second
	MAX_CONNS    = 500
	MAX_MSG_SIZE = 100 // input validation byte limit
)

var (
	activeConns int64
	totalConns  int64
)

// handleConnection reads from the client, validates input, echoes a response.
// A deadline is set to prevent slow/hanging clients (Slowloris defence).
func handleConnection(conn net.Conn) {
	atomic.AddInt64(&activeConns, 1)
	atomic.AddInt64(&totalConns, 1)
	defer func() {
		atomic.AddInt64(&activeConns, -1)
		conn.Close()
	}()

	log.Printf("[CONNECT] Client: %s | Active: %d", conn.RemoteAddr(), atomic.LoadInt64(&activeConns))

	// Timeout: prevent hanging/slow connections
	if err := conn.SetDeadline(time.Now().Add(CONN_TIMEOUT)); err != nil {
		log.Printf("[ERROR] SetDeadline: %v", err)
		return
	}

	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("[DISCONNECT] %s | %v", conn.RemoteAddr(), err)
			return
		}

		// Input validation: reject oversized messages
		if n > MAX_MSG_SIZE {
			conn.Write([]byte("ERROR: message too large\n"))
			log.Printf("[REJECTED] Oversized msg from %s (%d bytes)", conn.RemoteAddr(), n)
			return
		}

		msg := string(buf[:n])
		log.Printf("[RECV] %s → %q", conn.RemoteAddr(), msg)

		conn.Write([]byte(fmt.Sprintf("ECHO: %s\n", msg)))

		// Reset deadline after each successful exchange
		conn.SetDeadline(time.Now().Add(CONN_TIMEOUT))
	}
}

// statsReporter logs goroutine count, active connections, and total connections every 2s.
func statsReporter(quit <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			g := runtime.NumGoroutine()
			a := atomic.LoadInt64(&activeConns)
			t := atomic.LoadInt64(&totalConns)
			log.Printf("[METRICS] goroutines=%d active_conns=%d total_conns=%d", g, a, t)
			if g > 300 {
				log.Printf("[WARN] goroutine count high (%d) — possible goroutine leak!", g)
			}
		case <-quit:
			return
		}
	}
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	addr := fmt.Sprintf("%s:%s", HOST, PORT)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[FATAL] Listen failed: %v", err)
	}
	defer listener.Close()

	log.Printf("[SERVER] Listening on %s | timeout=%s max_conns=%d", addr, CONN_TIMEOUT, MAX_CONNS)

	quit := make(chan struct{})
	go statsReporter(quit)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("[SERVER] Shutting down...")
		close(quit)
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[SERVER] Accept loop stopped: %v", err)
			return
		}

		// Connection cap enforced via atomic counter (semaphore pattern)
		if atomic.LoadInt64(&activeConns) >= int64(MAX_CONNS) {
			log.Printf("[LIMIT] Cap reached (%d), rejecting %s", MAX_CONNS, conn.RemoteAddr())
			conn.Write([]byte("ERROR: server at capacity\n"))
			conn.Close()
			continue
		}

		go handleConnection(conn)
	}
}
