# LAB9-Build-and-Analyze-a-Client-Server-Socket-System
This is project that I was committed during studied in  MUICT.
# Lab 9: Concurrent TCP Server System — Code Documentation

**Course:** Network Administration  
**Lab Title:** Build a Concurrent, Observable, and Secure TCP Server in Go  
**Files:** `server.go`, `client.go`

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [server.go](#servergo)
   - [Constants](#constants)
   - [Part A — Basic Concurrent Server](#part-a--basic-concurrent-server)
   - [Part B — Timeout Server](#part-b--timeout-server)
   - [Part E — Secure Server](#part-e--secure-server)
   - [Part F — TLS Server](#part-f--tls-server)
4. [client.go](#clientgo)
   - [Part C — Load Generator](#part-c--load-generator)
   - [Part F — TLS Client](#part-f--tls-client)
   - [Part F — Certificate Generator](#part-f--certificate-generator)
5. [Concurrency Model](#concurrency-model)
6. [Security Mechanisms](#security-mechanisms)
7. [Usage Reference](#usage-reference)

---

## Overview

This system implements a multi-mode TCP server and client in Go, designed to demonstrate concurrent connection handling, timeout management, security hardening, and TLS encryption. Both programs are contained in a single file each (`server.go` and `client.go`), with runtime behaviour controlled via command-line arguments.

---

## System Architecture

```
┌─────────────────────────────────────────────────┐
│                   client.go                     │
│                                                 │
│  load     → 100 goroutines → :8080 (TCP)        │
│  tls      → 1 TLS client   → :8443 (TLS)        │
│  gencert  → generates cert.pem + key.pem        │
└─────────────────────────┬───────────────────────┘
                          │
              TCP / TLS connection
                          │
┌─────────────────────────▼───────────────────────┐
│                   server.go                     │
│                                                 │
│  basic    → goroutine per connection  (:8080)   │
│  timeout  → goroutine + deadlines    (:8080)    │
│  secure   → semaphore + validation   (:8080)    │
│  tls      → TLS encrypted server     (:8443)    │
└─────────────────────────────────────────────────┘
```

---

## server.go

### Constants

| Constant | Value | Purpose |
|---|---|---|
| `TCP_PORT` | `:8080` | Listening port for non-TLS modes |
| `TLS_PORT` | `:8443` | Listening port for TLS mode |
| `TIMEOUT` | `5s` | Read/write deadline per connection |
| `MAX_CONNECTIONS` | `10` | Maximum simultaneous connections (Part E) |
| `MAX_INPUT_SIZE` | `100 bytes` | Maximum accepted payload size (Part E) |

---

### Part A — Basic Concurrent Server

**Function:** `handleBasic(conn net.Conn)` / `runBasic()`

**Purpose:** Demonstrates the fundamental goroutine-per-connection concurrency model in Go.

**Behaviour:**
- Listens on `:8080` via `net.Listen()`
- On each accepted connection, spawns a new goroutine with `go handleBasic(conn)`
- Reads up to 1024 bytes from the client
- Responds with a static acknowledgement string
- Defers `conn.Close()` to ensure the connection is released on function exit

**Key Design Decision:**  
The use of `go handleBasic(conn)` means each connection is handled independently and concurrently. The main loop is never blocked by an individual client, enabling high throughput without OS-level thread overhead.

```go
for {
    conn, err := ln.Accept()
    if err != nil { continue }
    go handleBasic(conn)   // non-blocking dispatch
}
```

**Limitation:** No timeout is applied. A slow or unresponsive client will hold its goroutine indefinitely, which is addressed in Part B.

---

### Part B — Timeout Server

**Function:** `handleTimeout(conn net.Conn)` / `runTimeout()`

**Purpose:** Introduces connection deadlines to prevent resource exhaustion from slow or stalled clients.

**Behaviour:**
- Sets an initial deadline of `TIMEOUT` (5 seconds) via `conn.SetDeadline()`
- If the client does not send data within the deadline, the read operation returns a `net.Error` with `Timeout() == true`
- The deadline is reset before the write response to give the server a fresh window for the outgoing data
- Distinguishes timeout errors from other I/O errors for accurate logging

**Timeout Error Handling:**
```go
if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
    fmt.Printf("[Timeout] Client %s timed out\n", conn.RemoteAddr())
}
```

**Security Relevance:**  
Without read deadlines, a server is vulnerable to Slowloris-style attacks, where an attacker opens many connections and sends data extremely slowly, eventually exhausting all available goroutines or file descriptors.

---

### Part E — Secure Server

**Function:** `handleSecure(conn net.Conn)` / `runSecure()`

**Purpose:** Implements three defensive mechanisms: connection limiting, input validation, and structured logging.

#### 1. Connection Limiting via Semaphore

A buffered channel of capacity `MAX_CONNECTIONS` acts as a semaphore. Each goroutine must acquire a slot before proceeding; it blocks if the channel is full.

```go
var semaphore = make(chan struct{}, MAX_CONNECTIONS)

// Acquire
semaphore <- struct{}{}

// Release (deferred)
defer func() { <-semaphore }()
```

This ensures no more than `MAX_CONNECTIONS` clients are actively processed at any time, protecting against resource exhaustion.

#### 2. Active Connection Counter

An atomic integer tracks live connections for observability without requiring a mutex:

```go
var activeConnections int64
count := atomic.AddInt64(&activeConnections, 1)
defer atomic.AddInt64(&activeConnections, -1)
```

#### 3. Input Validation

Payloads exceeding `MAX_INPUT_SIZE` bytes are rejected before processing:

```go
if n > MAX_INPUT_SIZE {
    conn.Write([]byte("ERROR: Input too large\n"))
    return
}
```

This mitigates buffer-based attacks and enforces an application-level protocol boundary.

#### 4. Structured Logging

All significant events (connection open/close, timeouts, rejections) are logged with a timestamp via the `log()` helper:

```go
func log(format string, args ...interface{}) {
    ts := time.Now().Format("2006-01-02 15:04:05")
    fmt.Printf("[%s] "+format+"\n", append([]interface{}{ts}, args...)...)
}
```

---

### Part F — TLS Server

**Function:** `handleTLS(conn net.Conn)` / `runTLS()`

**Purpose:** Encrypts all client-server communication using TLS 1.2 or higher.

**Behaviour:**
- Loads a certificate and private key from `cert.pem` and `key.pem`
- Configures a `tls.Config` with `MinVersion: tls.VersionTLS12` to reject legacy protocols
- Listens on `:8443` via `tls.Listen()`, which wraps the standard TCP listener with TLS negotiation
- The `handleTLS` function is structurally identical to `handleSecure` — TLS is transparent at the application layer once the connection is established

**TLS Configuration:**
```go
config := &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
}
ln, err := tls.Listen("tcp", TLS_PORT, config)
```

**Certificate Requirement:**  
`cert.pem` and `key.pem` must be present in the working directory. These are generated by running `go run client.go gencert`.

---

## client.go

### Part C — Load Generator

**Function:** `sendMessage(id int, wg *sync.WaitGroup)` / `runLoad()`

**Purpose:** Simulates 100 concurrent clients connecting to the server simultaneously, for stress testing and Wireshark analysis.

**Behaviour:**
- Spawns `NUM_CLIENTS` (100) goroutines simultaneously
- Each goroutine dials the server with a timeout via `net.DialTimeout()`
- Sends a uniquely identified message (e.g., `"Hello from client 42"`)
- Reads and prints the server's response
- Uses `sync.WaitGroup` to block `main()` until all goroutines have completed
- Reports total elapsed time upon completion

**Synchronisation:**
```go
var wg sync.WaitGroup
for i := 1; i <= NUM_CLIENTS; i++ {
    wg.Add(1)
    go sendMessage(i, &wg)
}
wg.Wait()
```

**Observability Note:**  
Running this client while capturing traffic in Wireshark (filter: `tcp.port == 8080`) will reveal parallel TCP streams, varying sequence numbers, and RTT differences across connections.

---

### Part F — TLS Client

**Function:** `runTLSClient()`

**Purpose:** Establishes a TLS connection to the TLS server and displays handshake metadata.

**Behaviour:**
- Connects to `:8443` using `tls.Dial()` with `InsecureSkipVerify: true` (appropriate only for self-signed lab certificates)
- Prints the negotiated TLS version, cipher suite, and session resumption status
- Sends a test message and prints the server's encrypted response

**Handshake Inspection:**
```go
state := conn.ConnectionState()
fmt.Printf("TLS Version  : 0x%04x\n", state.Version)
fmt.Printf("Cipher Suite : %s\n", tls.CipherSuiteName(state.CipherSuite))
fmt.Printf("Resumed      : %v\n", state.DidResume)
```

> **Note:** `InsecureSkipVerify: true` disables certificate chain validation. This is acceptable in a controlled lab environment but must never be used in production systems.

---

### Part F — Certificate Generator

**Function:** `runGenCert()`

**Purpose:** Generates a self-signed X.509 certificate and EC private key for use by the TLS server.

**Process:**
1. Generates an ECDSA P-256 private key via `crypto/rand`
2. Constructs an `x509.Certificate` template with `localhost` as the Common Name and SAN
3. Self-signs the certificate (issuer == subject)
4. Encodes and writes `cert.pem` (DER certificate) and `key.pem` (EC private key) in PEM format

**Output Files:**

| File | Contents | Format |
|---|---|---|
| `cert.pem` | Self-signed X.509 certificate | PEM (`CERTIFICATE`) |
| `key.pem` | ECDSA P-256 private key | PEM (`EC PRIVATE KEY`) |

**Certificate Properties:**
- Algorithm: ECDSA with P-256 curve
- Validity: 1 year from generation
- Key Usage: `Digital Signature`, `Server Authentication`
- SAN: `localhost`

---

## Concurrency Model

Go's concurrency model differs fundamentally from OS thread-based approaches:

| Property | OS Thread | Go Goroutine |
|---|---|---|
| Stack size (initial) | ~1–8 MB | ~2 KB |
| Scheduled by | Operating System | Go runtime |
| Context switch cost | High (kernel mode) | Low (user space) |
| Suitable for 10,000 conns | No (memory-intensive) | Yes |

The Go runtime multiplexes goroutines onto a pool of OS threads using an M:N scheduling model. Under the hood, the `net` package uses `epoll` (Linux) or `kqueue` (macOS/BSD) for non-blocking I/O, meaning goroutines are suspended while waiting for I/O and resumed only when data is ready — without blocking an OS thread.

---

## Security Mechanisms

| Mechanism | Implemented In | Threat Mitigated |
|---|---|---|
| Read/write deadlines | Parts B, E, F | Slowloris, hung connections |
| Connection semaphore | Part E | Resource exhaustion, DoS |
| Input size validation | Parts E, F | Buffer overflow, injection |
| Timestamped logging | Parts E, F | Audit trail, incident response |
| TLS 1.2+ enforcement | Part F | Eavesdropping, MITM attacks |
| Minimum TLS version | Part F | Downgrade attacks (SSL/TLS 1.0/1.1) |

---

## Usage Reference

### server.go

```bash
go run server.go basic     # Part A — basic concurrent server      (:8080)
go run server.go timeout   # Part B — server with timeouts         (:8080)
go run server.go secure    # Part E — hardened server              (:8080)
go run server.go tls       # Part F — TLS encrypted server         (:8443)
```

### client.go

```bash
go run client.go load      # Part C — 100 concurrent clients  → :8080
go run client.go tls       # Part F — single TLS client       → :8443
go run client.go gencert   # Part F — generate cert.pem + key.pem
```

### Recommended Test Sequence

```bash
# Part A / B / C
go run server.go basic          # Terminal 1
go run client.go load           # Terminal 2

# Part F (TLS)
go run client.go gencert        # once only
go run server.go tls            # Terminal 1
go run client.go tls            # Terminal 2

# Wireshark (Part D)
# Filter: tcp.port == 8080
# Run load client while capturing to observe parallel TCP streams
```

---

*Documentation prepared for Lab 9 — Network Administration*
